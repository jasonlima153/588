#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreLocation/CoreLocation.h>
#import <Security/Security.h>

// ============================================================================
// 一、运行时动态类与方法安全声明
// ============================================================================
@interface AppService : NSObject
+ (id)sharedInstance;
- (void)startSocketService;
@end

@interface SPSocket : NSObject
+ (id)sharedInstance;
- (void)socketHeartheadReq;
@end

@interface IMAutoConnectSocket : NSObject
+ (id)sharedInstance;
- (void)resetBeforeReconnect;
@end

// ============================================================================
// 二、辅助函数：获取分身唯一ID
// ============================================================================
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
// 三、音频保活引擎（静音循环播放）
// ============================================================================
static AVAudioPlayer *keepAliveAudioPlayer = nil;
static NSString *silentAudioPath = nil;

static const unsigned char silent_mp3[] = {
    0xFF, 0xFB, 0x90, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1B, 0x54, 0x49, 0x54, 0x32, 0x00, 0x00,
    0x00, 0x0C, 0x00, 0x00, 0x03, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const unsigned int silent_mp3_len = 48;

static void releaseSilentAudio(void) {
    if (!silentAudioPath) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        silentAudioPath = [docs stringByAppendingPathComponent:@"__keepalive__.mp3"];
        NSData *data = [NSData dataWithBytes:silent_mp3 length:silent_mp3_len];
        [data writeToFile:silentAudioPath atomically:YES];
    }
}

static void startAudioKeepAlive(void) {
    if (keepAliveAudioPlayer) return;
    releaseSilentAudio();
    if (!silentAudioPath) return;

    NSError *error = nil;
    AVAudioSession *session = [AVAudioSession sharedInstance];
    [session setCategory:AVAudioSessionCategoryPlayback
             withOptions:AVAudioSessionCategoryOptionMixWithOthers
                   error:&error];
    [session setActive:YES error:&error];

    NSURL *url = [NSURL fileURLWithPath:silentAudioPath];
    keepAliveAudioPlayer = [[AVAudioPlayer alloc] initWithContentsOfURL:url error:&error];
    if (keepAliveAudioPlayer) {
        keepAliveAudioPlayer.numberOfLoops = -1;
        keepAliveAudioPlayer.volume = 0.0;
        [keepAliveAudioPlayer prepareToPlay];
        [keepAliveAudioPlayer play];
        NSLog(@"[MultiPush] 静音音频保活已启动");
    } else {
        NSLog(@"[MultiPush] 音频启动失败: %@", error);
    }
}

static void stopAudioKeepAlive(void) {
    if (keepAliveAudioPlayer) {
        [keepAliveAudioPlayer stop];
        keepAliveAudioPlayer = nil;
        [[AVAudioSession sharedInstance] setActive:NO withOptions:AVAudioSessionSetActiveOptionNotifyOthersOnDeactivation error:nil];
        NSLog(@"[MultiPush] 音频保活已停止");
    }
}

// ============================================================================
// 四、为 SPSocket 设置 VoIP 标志
// ============================================================================
%hook SPSocket

- (void)connectToServer:(id)server {
    %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSURLSession *session = [NSURLSession sharedSession];
        [session getAllTasksWithCompletionHandler:^(NSArray<__kindof NSURLSessionTask *> *tasks) {
            for (NSURLSessionTask *task in tasks) {
                NSString *host = task.originalRequest.URL.host ?: @"";
                NSString *scheme = task.originalRequest.URL.scheme ?: @"";
                if ([host containsString:@"socket"] || [scheme isEqualToString:@"ws"] || [scheme isEqualToString:@"wss"]) {
                    [task setValue:@(NSURLNetworkServiceTypeVoIP) forKey:@"networkServiceType"];
                    NSLog(@"[MultiPush] 已设置 Socket 任务为 VoIP 类型");
                }
            }
        }];
    });
}

%end

// ============================================================================
// 五、Keychain 动态隔离区（kSecAttrComment 方案）
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
// 六、本地持久化与 Token 缓存键名防御性拦截
// ============================================================================
%hook NSUserDefaults

- (void)setObject:(id)value forKey:(NSString *)defaultName {
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
// 七、深度逆向突破：强制打破后台卡死、无限旋转的连接重建引擎
// ============================================================================
static UIBackgroundTaskIdentifier safeBgTaskToken = UIBackgroundTaskInvalid;
static NSTimer *heartbeatTimer = nil;

%hook AppDelegate

- (void)applicationDidEnterBackground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身进入后台，启动音频+后台任务双重保活");

    // 1. 启动音频保活
    startAudioKeepAlive();

    // 2. 申请后台任务
    safeBgTaskToken = [application beginBackgroundTaskWithExpirationHandler:^{
        NSLog(@"[MultiPush] 后台倒计时用尽，断开 Socket 状态锁");
        [application endBackgroundTask:safeBgTaskToken];
        safeBgTaskToken = UIBackgroundTaskInvalid;
    }];

    // 3. 定时心跳（每 90 秒）
    if (heartbeatTimer) [heartbeatTimer invalidate];
    heartbeatTimer = [NSTimer scheduledTimerWithTimeInterval:90.0 repeats:YES block:^(NSTimer * _Nonnull timer) {
        id spSocket = [NSClassFromString(@"SPSocket") sharedInstance];
        SEL heartbeatSel = NSSelectorFromString(@"socketHeartheadReq");
        if ([spSocket respondsToSelector:heartbeatSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            [spSocket performSelector:heartbeatSel];
#pragma clang diagnostic pop
            NSLog(@"[MultiPush] 后台心跳已发送");
        }
    }];
    [[NSRunLoop currentRunLoop] addTimer:heartbeatTimer forMode:NSRunLoopCommonModes];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 分身重回前台 -> 触发物理级长连接强制重建！");

    // 清理后台资源
    stopAudioKeepAlive();

    if (heartbeatTimer) {
        [heartbeatTimer invalidate];
        heartbeatTimer = nil;
    }

    if (safeBgTaskToken != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:safeBgTaskToken];
        safeBgTaskToken = UIBackgroundTaskInvalid;
    }

    // 【深度修复核心逻辑】
    // 1. 获取 SPSocket 实例
    id spSocket = [NSClassFromString(@"SPSocket") sharedInstance];
    if (spSocket) {
        NSLog(@"[MultiPush] 正在强制重置 SPSocket 的内部卡死状态...");

        // 2. 强行破坏 _isSocketLoginSuccess，逼迫重走网络握手
        @try {
            [spSocket setValue:@(NO) forKey:@"_isSocketLoginSuccess"];
            NSLog(@"[MultiPush] 已成功将 _isSocketLoginSuccess 置为 NO");
        } @catch (NSException *exception) {
            NSLog(@"[MultiPush] 警告: 无法直接通过 KVC 写入 _isSocketLoginSuccess: %@", exception.reason);
        }

        // 3. 强行清空重连计数器
        id autoConnect = [NSClassFromString(@"IMAutoConnectSocket") sharedInstance];
        if (autoConnect) {
            @try {
                [autoConnect setValue:@(0) forKey:@"reconnectAttempts"];
                NSLog(@"[MultiPush] 已成功重置 reconnectAttempts 为 0");
            } @catch (NSException *exception) {
                NSLog(@"[MultiPush] 警告: 无法重置 reconnectAttempts: %@", exception.reason);
            }
            // 尝试直接调用 resetBeforeReconnect
            SEL resetSel = NSSelectorFromString(@"resetBeforeReconnect");
            if ([autoConnect respondsToSelector:resetSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                [autoConnect performSelector:resetSel];
#pragma clang diagnostic pop
                NSLog(@"[MultiPush] 已调用 IMAutoConnectSocket resetBeforeReconnect");
            }
        }
    }

    // 4. 强制调度总管服务：直接整个重新初始化 Socket
    AppService *appService = [NSClassFromString(@"AppService") sharedInstance];
    if (appService && [appService respondsToSelector:@selector(startSocketService)]) {
        NSLog(@"[MultiPush] 正在触发总管级 [AppService startSocketService] 强行拉起新通道...");
        [appService startSocketService];
    }
}

%end

// ============================================================================
// 八、构造器注入
// ============================================================================
%ctor {
    @autoreleasepool {
        NSLog(@"[MultiPush] 多实例动态网络重组引擎部署中...");

        MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemCopyMatching, (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemUpdate, (void *)new_SecItemUpdate, (void **)&orig_SecItemUpdate);
        MSHookFunction((void *)SecItemDelete, (void *)new_SecItemDelete, (void **)&orig_SecItemDelete);

        // 预释放音频文件
        releaseSilentAudio();
    }
}
