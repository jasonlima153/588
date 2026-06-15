#import <UIKit/UIKit.h>
#import <Security/Security.h>

// ============================================================================
// 一、 运行时动态类与方法安全声明
// ============================================================================
@interface AppService : NSObject
+ (id)sharedInstance;
- (void)startSocketService;
@end

// 获取当前分身沙盒的唯一标识
static NSString* getSafeInstanceIdentifier(void) {
    static NSString *instanceID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *homeDir = NSHomeDirectory();
        if (homeDir.length > 0) {
            instanceID = [homeDir lastPathComponent];
        } else {
            instanceID = @"DefaultClone";
        }
    });
    return instanceID;
}

// ============================================================================
// 二、 Keychain 动态隔离区（稳定版）
// ============================================================================
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);

static CFDictionaryRef createIsolatedAttributes(CFDictionaryRef dict, BOOL isQuery) {
    if (!dict) return NULL;
    NSMutableDictionary *newDict = [(__bridge NSDictionary *)dict mutableCopy];
    NSString *instanceID = getSafeInstanceIdentifier();
    newDict[(__bridge id)kSecAttrComment] = instanceID;
    return (__bridge_retained CFDictionaryRef)newDict;
}

OSStatus new_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFDictionaryRef isolated = createIsolatedAttributes(attributes, NO);
    OSStatus status = orig_SecItemAdd(isolated ?: attributes, result);
    if (isolated) CFRelease(isolated);
    return status;
}

OSStatus new_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef isolated = createIsolatedAttributes(query, YES);
    OSStatus status = orig_SecItemCopyMatching(isolated ?: query, result);
    if (isolated) CFRelease(isolated);
    return status;
}

OSStatus new_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    CFDictionaryRef isolatedQuery = createIsolatedAttributes(query, YES);
    CFDictionaryRef isolatedAttrs = createIsolatedAttributes(attributesToUpdate, NO);
    OSStatus status = orig_SecItemUpdate(isolatedQuery ?: query, isolatedAttrs ?: attributesToUpdate);
    if (isolatedQuery) CFRelease(isolatedQuery);
    if (isolatedAttrs) CFRelease(isolatedAttrs);
    return status;
}

OSStatus new_SecItemDelete(CFDictionaryRef query) {
    CFDictionaryRef isolated = createIsolatedAttributes(query, YES);
    OSStatus status = orig_SecItemDelete(isolated ?: query);
    if (isolated) CFRelease(isolated);
    return status;
}

// ============================================================================
// 三、 本地持久化缓存隔离 (NSUserDefaults)
// ============================================================================
%hook NSUserDefaults

- (void)setObject:(id)value forKey:(NSString *)defaultName {
    if ([defaultName isEqualToString:@"sppush.cacheDeviceTokenKey"]) {
        NSString *isolatedKey = [NSString stringWithFormat:@"sppush.cacheDeviceTokenKey_%@", getSafeInstanceIdentifier()];
        %orig(value, isolatedKey);
        return;
    }
    %orig;
}

- (id)objectForKey:(NSString *)defaultName {
    if ([defaultName isEqualToString:@"sppush.cacheDeviceTokenKey"]) {
        NSString *isolatedKey = [NSString stringWithFormat:@"sppush.cacheDeviceTokenKey_%@", getSafeInstanceIdentifier()];
        return %orig(isolatedKey);
    }
    return %orig;
}

%end

// ============================================================================
// 四、 核心杀招：多实例底层 RunLoop 物理强行常驻引擎
// ============================================================================
static UIBackgroundTaskIdentifier dynamicBgTask = UIBackgroundTaskInvalid;
static NSTimer *keepAliveLoopTimer = nil;

// 核心保活：强制无限续航长连接任务
void initiateInfiniteKeepAliveLoop(UIApplication *application) {
    // 1. 如果当前任务已存在，先平滑销毁
    if (dynamicBgTask != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:dynamicBgTask];
        dynamicBgTask = UIBackgroundTaskInvalid;
    }
    
    // 2. 强行向系统申请全新的后台执行时间
    dynamicBgTask = [application beginBackgroundTaskWithExpirationHandler:^{
        NSLog(@"[MultiPush] 警告：12秒期限临界点到达！强制进行物理级线程重启续命...");
        
        // 当系统试图挂起（杀死）我们的瞬间，通过自我迭代，强行在底层无限循环续命
        initiateInfiniteKeepAliveLoop(application);
    }];
    
    // 3. 每当系统要切断网络时，主动强制发送长连接活性探测包，死死顶住 Socket
    id spSocket = [NSClassFromString(@"SPSocket") sharedInstance];
    SEL heartbeatSel = NSSelectorFromString(@"socketHeartheadReq");
    if ([spSocket respondsToSelector:heartbeatSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [spSocket performSelector:heartbeatSel];
#pragma clang diagnostic pop
        NSLog(@"[MultiPush] 成功在锁屏后台灌入强行心跳");
    }
}

%hook AppDelegate

- (void)applicationDidEnterBackground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身应用切入后台/锁屏 -> 启动商业级常驻保活引擎");
    
    // 开启物理级无限后台循环
    initiateInfiniteKeepAliveLoop(application);
    
    // 建立后台高频强行重连定时器，每 10 秒死死守住 Socket 活性，彻底打破 12 秒必断的死穴
    if (!keepAliveLoopTimer) {
        keepAliveLoopTimer = [NSTimer scheduledTimerWithTimeInterval:10.0 
                                                             repeats:YES 
                                                               block:^(NSTimer * _Nonnull timer) {
            NSLog(@"[MultiPush] 锁屏状态守护：正在强制唤醒 Socket 线程状态...");
            
            id spSocket = [NSClassFromString(@"SPSocket") sharedInstance];
            if (spSocket) {
                // 重置卡死标记
                @try {
                    [spSocket setValue:@(YES) forKey:@"_isSocketLoginSuccess"];
                } @catch (NSException *e) {}
            }
            
            // 触发长连接守护
            AppService *appService = [NSClassFromString(@"AppService") sharedInstance];
            if (appService && [appService respondsToSelector:@selector(startSocketService)]) {
                [appService startSocketService];
            }
        }];
        // 将定时器强行塞入系统最高等级的 RunLoop 通道，确保锁屏也不被冻结
        [[NSRunLoop currentRunLoop] addTimer:keepAliveLoopTimer forMode:NSRunLoopCommonModes];
    }
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身应用返回前台 -> 释放常驻挂机组件，回归常规模式");
    
    // 清理后台常驻组件，防止前台产生内存积压
    if (keepAliveLoopTimer) {
        [keepAliveLoopTimer invalidate];
        keepAliveLoopTimer = nil;
    }
    
    if (dynamicBgTask != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:dynamicBgTask];
        dynamicBgTask = UIBackgroundTaskInvalid;
    }
    
    // 前台干净重建连接
    AppService *appService = [NSClassFromString(@"AppService") sharedInstance];
    if (appService && [appService respondsToSelector:@selector(startSocketService)]) {
        [appService startSocketService];
    }
}

%end

// ============================================================================
// 五、 构造器注入
// ============================================================================
%ctor {
    @autoreleasepool {
        MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemCopyMatching, (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemUpdate, (void *)new_SecItemUpdate, (void **)&orig_SecItemUpdate);
        MSHookFunction((void *)SecItemDelete, (void *)new_SecItemDelete, (void **)&orig_SecItemDelete);
    }
}
