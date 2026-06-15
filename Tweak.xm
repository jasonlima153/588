#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <CoreLocation/CoreLocation.h>
#import <Security/Security.h>

// ============================================================================
// 一、运行时声明
// ============================================================================
@interface AppService : NSObject
+ (id)sharedInstance;
- (void)startSocketService;
@end

@interface SPSocket : NSObject
+ (id)sharedInstance;
- (void)socketHeartheadReq;
@end

// ============================================================================
// 二、辅助函数：获取分身唯一ID
// ============================================================================
static NSString* getInstanceID(void) {
    static NSString *instanceID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *home = NSHomeDirectory();
        instanceID = [home lastPathComponent] ?: @"UnknownClone";
    });
    return instanceID;
}

// ============================================================================
// 三、音频保活引擎（静音循环播放）
// ============================================================================
static AVAudioPlayer *keepAliveAudioPlayer = nil;
static NSString *silentAudioPath = nil;

// 内嵌极短无声音频（MP3 最小帧，长度约 200ms，完全静音）
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
        keepAliveAudioPlayer.numberOfLoops = -1;  // 无限循环
        keepAliveAudioPlayer.volume = 0.0;       // 静音
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
// 四、为 SPSocket 设置 VoIP 标志（降低后台断连概率）
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
                    if (@available(iOS 13.0, *)) {
                        task.networkServiceType = NSURLSessionTaskNetworkServiceTypeVoIP;
                    } else {
                        [task setValue:@(NSURLRequestNetworkServiceTypeVoIP) forKey:@"networkServiceType"];
                    }
                    NSLog(@"[MultiPush] 已设置 Socket 任务为 VoIP 类型");
                }
            }
        }];
    });
}

%end

// ============================================================================
// 五、Keychain 隔离（安全版，使用 kSecAttrComment）
// ============================================================================
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef, CFTypeRef *);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef, CFDictionaryRef);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef);

static CFDictionaryRef addInstanceComment(CFDictionaryRef dict, BOOL isQuery) {
    if (!dict) return NULL;
    NSMutableDictionary *newDict = [(__bridge NSDictionary *)dict mutableCopy];
    NSString *instID = getInstanceID();
    newDict[(__bridge id)kSecAttrComment] = instID;
    return (__bridge_retained CFDictionaryRef)newDict;
}

OSStatus new_SecItemAdd(CFDictionaryRef attrs, CFTypeRef *result) {
    CFDictionaryRef isolated = addInstanceComment(attrs, NO);
    OSStatus status = orig_SecItemAdd(isolated ?: attrs, result);
    if (isolated) CFRelease(isolated);
    return status;
}

OSStatus new_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef isolated = addInstanceComment(query, YES);
    OSStatus status = orig_SecItemCopyMatching(isolated ?: query, result);
    if (isolated) CFRelease(isolated);
    return status;
}

OSStatus new_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attrs) {
    CFDictionaryRef isolatedQuery = addInstanceComment(query, YES);
    CFDictionaryRef isolatedAttrs = addInstanceComment(attrs, NO);
    OSStatus status = orig_SecItemUpdate(isolatedQuery ?: query, isolatedAttrs ?: attrs);
    if (isolatedQuery) CFRelease(isolatedQuery);
    if (isolatedAttrs) CFRelease(isolatedAttrs);
    return status;
}

OSStatus new_SecItemDelete(CFDictionaryRef query) {
    CFDictionaryRef isolated = addInstanceComment(query, YES);
    OSStatus status = orig_SecItemDelete(isolated ?: query);
    if (isolated) CFRelease(isolated);
    return status;
}

// ============================================================================
// 六、AppDelegate 后台保活 + 前后台切换控制
// ============================================================================
static UIBackgroundTaskIdentifier bgTask = UIBackgroundTaskInvalid;
static NSTimer *heartbeatTimer = nil;

%hook AppDelegate

- (void)applicationDidEnterBackground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 进入后台，启动音频+后台任务双重保活");

    // 1. 启动音频保活（核心）
    startAudioKeepAlive();

    // 2. 申请后台任务（作为辅助）
    bgTask = [application beginBackgroundTaskWithExpirationHandler:^{
        NSLog(@"[MultiPush] 后台任务即将过期，但音频仍在运行，不会挂起");
        [application endBackgroundTask:bgTask];
        bgTask = UIBackgroundTaskInvalid;
    }];

    // 3. 定时心跳（每 90 秒发送一次，保持 socket 活跃）
    if (heartbeatTimer) [heartbeatTimer invalidate];
    heartbeatTimer = [NSTimer scheduledTimerWithTimeInterval:90.0 repeats:YES block:^(NSTimer * _Nonnull timer) {
        SPSocket *sp = [NSClassFromString(@"SPSocket") sharedInstance];
        if ([sp respondsToSelector:@selector(socketHeartheadReq)]) {
            [sp performSelector:@selector(socketHeartheadReq)];
            NSLog(@"[MultiPush] 后台心跳已发送");
        }
    }];
    [[NSRunLoop currentRunLoop] addTimer:heartbeatTimer forMode:NSRunLoopCommonModes];
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 回到前台，停止音频保活并清理后台任务");

    stopAudioKeepAlive();

    if (heartbeatTimer) {
        [heartbeatTimer invalidate];
        heartbeatTimer = nil;
    }

    if (bgTask != UIBackgroundTaskInvalid) {
        [application endBackgroundTask:bgTask];
        bgTask = UIBackgroundTaskInvalid;
    }

    // 重连 Socket
    AppService *service = [NSClassFromString(@"AppService") sharedInstance];
    if ([service respondsToSelector:@selector(startSocketService)]) {
        [service startSocketService];
    }
}

%end

// ============================================================================
// 七、构造器
// ============================================================================
%ctor {
    @autoreleasepool {
        NSLog(@"[MultiPush] 强化版后台保活引擎加载中...");

        // 钩子 Keychain
        MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemCopyMatching, (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
        MSHookFunction((void *)SecItemUpdate, (void *)new_SecItemUpdate, (void **)&orig_SecItemUpdate);
        MSHookFunction((void *)SecItemDelete, (void *)new_SecItemDelete, (void **)&orig_SecItemDelete);

        // 预释放音频文件，确保音频引擎随时可用
        releaseSilentAudio();
    }
}
