#import <UIKit/UIKit.h>
#import <Security/Security.h>

// ============================================================================
// 一、运行时动态类与方法安全声明
// ============================================================================
@interface AppService : NSObject
+ (id)sharedInstance;
- (void)startSocketService;
- (void)resetBeforeReconnect;
@end

@interface IMAutoConnectSocket : NSObject
+ (id)sharedInstance;
- (void)resetBeforeReconnect;
@end

// 获取当前分身沙盒的唯一标识（基于沙盒 UUID，天然物理隔离）
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
// 二、Keychain 动态隔离区（最安全方案：添加自定义属性，不破坏原始查询）
// ============================================================================
// 原理：为每个 Keychain 条目添加一个自定义属性 kSecAttrComment，
// 存入当前分身的 InstanceID。查询时也自动附加该条件，实现物理隔离。
// 这样既不影响系统原有的通配符查询，也能保证不同分身的条目互不可见。

static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);

// 辅助函数：为字典添加实例隔离属性（安全，不修改原始 Service/Account）
static CFDictionaryRef createIsolatedAttributes(CFDictionaryRef dict, BOOL isQuery) {
    if (!dict) return NULL;
    NSMutableDictionary *newDict = [(__bridge NSDictionary *)dict mutableCopy];
    NSString *instanceID = getSafeInstanceIdentifier();

    // 使用 kSecAttrComment 作为隔离标记（不会被系统其他逻辑依赖，非常安全）
    if (isQuery) {
        // 查询时：要求 kSecAttrComment 必须等于当前 InstanceID
        newDict[(__bridge id)kSecAttrComment] = instanceID;
    } else {
        // 添加或更新时：在条目中写入当前 InstanceID
        newDict[(__bridge id)kSecAttrComment] = instanceID;
    }
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
// 三、本地持久化与 Token 缓存键名防御性拦截（Hook NSUserDefaults）
// ============================================================================
%hook NSUserDefaults

- (void)setObject:(id)value forKey:(NSString *)defaultName {
    // 拦截报告中的关键缓存键
    if ([defaultName isEqualToString:@"sppush.cacheDeviceTokenKey"]) {
        NSString *isolatedKey = [NSString stringWithFormat:@"sppush.cacheDeviceTokenKey_%@", getSafeInstanceIdentifier()];
        NSLog(@"[MultiPush] 隔离 Token 缓存键: %@", isolatedKey);
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
// 四、稳扎稳打的客户端多实例连接守护与重连机制
// ============================================================================
static UIBackgroundTaskIdentifier safeBgTaskToken = UIBackgroundTaskInvalid;

%hook AppDelegate

- (void)applicationDidEnterBackground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身进入后台，开始合规短期保活");

    safeBgTaskToken = [application beginBackgroundTaskWithExpirationHandler:^{
        NSLog(@"[MultiPush] 后台时间耗尽，长连接进入休眠，等待前台唤醒");
        [application endBackgroundTask:safeBgTaskToken];
        safeBgTaskToken = UIBackgroundTaskInvalid;
    }];

    // 可选：发送一次心跳，告知服务器当前实例仍在后台
    id spSocket = [NSClassFromString(@"SPSocket") sharedInstance];
    if ([spSocket respondsToSelector:NSSelectorFromString(@"socketHeartheadReq")]) {
        [spSocket performSelector:NSSelectorFromString(@"socketHeartheadReq")];
    }
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身返回前台，触发重连恢复");

    if (safeBgTaskToken != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:safeBgTaskToken];
        safeBgTaskToken = UIBackgroundTaskInvalid;
    }

    // 优先尝试 AppService 的重置方法
    AppService *appService = [NSClassFromString(@"AppService") sharedInstance];
    if (appService) {
        SEL resetSel = NSSelectorFromString(@"resetBeforeReconnect");
        if ([appService respondsToSelector:resetSel]) {
            [appService performSelector:resetSel];
            NSLog(@"[MultiPush] 调用 AppService resetBeforeReconnect 重置连接");
        } else if ([appService respondsToSelector:@selector(startSocketService)]) {
            [appService startSocketService];
            NSLog(@"[MultiPush] 调用 AppService startSocketService 重建连接");
        }
    }

    // 备选：直接让 IMAutoConnectSocket 重置
    id autoConnect = [NSClassFromString(@"IMAutoConnectSocket") sharedInstance];
    if ([autoConnect respondsToSelector:@selector(resetBeforeReconnect)]) {
        [autoConnect performSelector:@selector(resetBeforeReconnect)];
        NSLog(@"[MultiPush] 调用 IMAutoConnectSocket resetBeforeReconnect");
    }
}

%end

// ============================================================================
// 五、构造器注入
// ============================================================================
%ctor {
    @autoreleasepool {
        NSLog(@"[MultiPush] 多实例隔离与重连引擎加载中...");

        // Hook Security.framework 底层 C 函数
        MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemCopyMatching, (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemUpdate, (void *)new_SecItemUpdate, (void **)&orig_SecItemUpdate);
        MSHookFunction((void *)SecItemDelete, (void *)new_SecItemDelete, (void **)&orig_SecItemDelete);

        NSLog(@"[MultiPush] Keychain 物理隔离已生效（使用 kSecAttrComment 标记）");
    }
}
