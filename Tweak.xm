#import <UIKit/UIKit.h>
#import <Security/Security.h>

// ============================================================================
// 一、 运行时动态类安全声明（严格遵循 558 报告标准）
// ============================================================================
@interface AppService : NSObject
+ (id)sharedInstance;
- (void)startSocketService;
@end

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
// 二、 Keychain 动态隔离区（kSecAttrComment 顶级安全方案）
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
// 四、 核心突变：通知广播震荡与系统级重连诱导
// ============================================================================
static UIBackgroundTaskIdentifier safeBgTaskToken = UIBackgroundTaskInvalid;

%hook AppDelegate

- (void)applicationDidEnterBackground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身应用切入后台/锁屏");
    
    safeBgTaskToken = [application beginBackgroundTaskWithExpirationHandler:^{
        [application endBackgroundTask:safeBgTaskToken];
        safeBgTaskToken = UIBackgroundTaskInvalid;
    }];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身返回前台 -> 正在执行系统级网络震荡重连机制...");
    
    if (safeBgTaskToken != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:safeBgTaskToken];
        safeBgTaskToken = UIBackgroundTaskInvalid;
    }
    
    // 核心打法：通过原应用总线上报"鉴权失效"和"强制下线"官方广播
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter] postNotificationName:@"notification.name.socket.authFailed" object:nil];
        [[NSNotificationCenter defaultCenter] postNotificationName:@"notification.name.socket.ForceOffline" object:nil];
        NSLog(@"[MultiPush] 成功向总线注入官方断线状态广播");
    });
    
    // 延迟 0.5 秒，在状态完全抹干净后，以最顶层的全新业务身份唤醒长连接服务
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        AppService *service = [NSClassFromString(@"AppService") sharedInstance];
        if (service && [service respondsToSelector:@selector(startSocketService)]) {
            NSLog(@"[MultiPush] 正在执行 startSocketService 初始化干净连接...");
            [service startSocketService];
        }
    });
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
