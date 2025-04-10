;; Title: SocialStack - Decentralized Social Network Protocol

;; Summary:
;; A comprehensive social networking protocol built on Stacks Layer 2,
;; providing secure user management, privacy controls, and relationship handling
;; with Bitcoin-level security guarantees.

;; Description:
;; SocialStack implements a robust social networking infrastructure with:
;; - Granular privacy controls and encryption support
;; - Rate-limiting and batch processing optimization
;; - Relationship management (friendships, blocking)
;; - Activity tracking and user status management
;; - Scalable data structures optimized for Layer 2
;; All operations are designed for maximum efficiency and minimal chain bloat.

;; Constants
;; =========

;; Error codes - Standardized error handling
(define-constant ERR_NOT_FOUND (err u100))
(define-constant ERR_ALREADY_EXISTS (err u101))
(define-constant ERR_UNAUTHORIZED (err u102))
(define-constant ERR_INVALID_INPUT (err u103))
(define-constant ERR_BLOCKED (err u104))
(define-constant ERR_DEACTIVATED (err u105))
(define-constant ERR_RATE_LIMITED (err u106))
(define-constant ERR_BATCH_FULL (err u107))
(define-constant ERR_BATCH_EXPIRED (err u108))

;; Status Constants - User account states
(define-constant STATUS_DEACTIVATED u0)
(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_SUSPENDED u2)

;; Relationship Constants - Friendship states
(define-constant FRIENDSHIP_PENDING u0)
(define-constant FRIENDSHIP_ACTIVE u1)
(define-constant FRIENDSHIP_BLOCKED u2)

;; Rate Limiting Constants - Platform protection
(define-constant MAX_ACTIONS_PER_DAY u100)
(define-constant MAX_FRIEND_REQUESTS_PER_DAY u20)
(define-constant MAX_STATUS_UPDATES_PER_DAY u24)
(define-constant RATE_LIMIT_RESET_PERIOD u86400) ;; 24 hours in seconds

;; Batch Processing Constants - Optimization parameters
(define-constant MIN_BATCH_SIZE u10)
(define-constant MAX_BATCH_SIZE u100)
(define-constant BATCH_EXPIRY_PERIOD u3600) ;; 1 hour in seconds

;; Data Maps
;; =========

;; Users - Core user data storage
(define-map Users 
    principal 
    {
        name: (string-ascii 64),
        status: uint,
        timestamp: uint,
        metadata: (optional (string-utf8 256)),
        deactivation-time: (optional uint),
        encryption-key: (optional (buff 32)),
        profile-image: (optional (string-utf8 256))
    }
)

;; UserPrivacy - Privacy settings storage
(define-map UserPrivacy
    principal
    {
        friend-list-visible: bool,
        status-visible: bool,
        metadata-visible: bool,
        last-seen-visible: bool,
        profile-image-visible: bool,
        encryption-enabled: bool,
        last-updated: uint
    }
)

;; RateLimits - Rate limiting data
(define-map RateLimits
    principal
    {
        daily-actions: uint,
        friend-requests: uint,
        status-updates: uint,
        last-reset: uint
    }
)

;; UserBatches - Batch processing management
(define-map UserBatches
    principal
    {
        message-counter: uint,
        last-batch-timestamp: uint,
        batch-size: uint,
        current-batch-items: uint,
        total-batches: uint
    }
)

;; UserActivity - User activity tracking
(define-map UserActivity
    principal
    {
        last-seen: uint,
        login-count: uint,
        total-actions: uint,
        last-action: uint
    }
)

;; Friendships - Relationship management
(define-map Friendships
    {
        user1: principal,
        user2: principal
    }
    {
        status: uint
    }
)

;; BlockedUsers - User blocking management
(define-map BlockedUsers
    {
        blocker: principal,
        blocked: principal
    }
    {
        timestamp: uint
    }
)

;; Private Functions
;; ================

;; Rate limit checker
(define-private (check-rate-limit (user principal) (action-type uint))
    (let
        (
            (rate-data (default-to 
                {
                    daily-actions: u0,
                    friend-requests: u0,
                    status-updates: u0,
                    last-reset: stacks-block-height
                }
                (map-get? RateLimits user)
            ))
            (current-time stacks-block-height)
            (should-reset (> (- current-time (get last-reset rate-data)) RATE_LIMIT_RESET_PERIOD))
        )
        (if should-reset
            (begin
                (map-set RateLimits user
                    {
                        daily-actions: u1,
                        friend-requests: (if (is-eq action-type u1) u1 u0),
                        status-updates: (if (is-eq action-type u2) u1 u0),
                        last-reset: current-time
                    }
                )
                true
            )
            (and
                (< (get daily-actions rate-data) MAX_ACTIONS_PER_DAY)
                (or 
                    (not (is-eq action-type u1))
                    (< (get friend-requests rate-data) MAX_FRIEND_REQUESTS_PER_DAY)
                )
                (or
                    (not (is-eq action-type u2))
                    (< (get status-updates rate-data) MAX_STATUS_UPDATES_PER_DAY)
                )
            )
        )
    )
)

;; Rate limit updater
(define-private (update-rate-limit (user principal) (action-type uint))
    (let
        (
            (rate-data (unwrap-panic (map-get? RateLimits user)))
        )
        (map-set RateLimits user
            (merge rate-data {
                daily-actions: (+ (get daily-actions rate-data) u1),
                friend-requests: (+ (get friend-requests rate-data) (if (is-eq action-type u1) u1 u0)),
                status-updates: (+ (get status-updates rate-data) (if (is-eq action-type u2) u1 u0))
            })
        )
    )
)

;; Activity tracker
(define-private (update-user-activity (user principal))
    (let
        (
            (current-time stacks-block-height)
            (activity (default-to
                {
                    last-seen: current-time,
                    login-count: u0,
                    total-actions: u0,
                    last-action: current-time
                }
                (map-get? UserActivity user)
            ))
        )
        (map-set UserActivity user
            (merge activity {
                last-seen: current-time,
                total-actions: (+ (get total-actions activity) u1),
                last-action: current-time
            })
        )
    )
)

;; Utility Functions
;; ================

;; Maximum of two uints
(define-private (max-uint (a uint) (b uint))
    (if (>= a b) a b)
)

;; Minimum of two uints
(define-private (min-uint (a uint) (b uint))
    (if (<= a b) a b)
)

;; Friendship checker
(define-private (are-friends (user1 principal) (user2 principal))
    (match (map-get? Friendships {user1: user1, user2: user2})
        friendship (is-eq (get status friendship) FRIENDSHIP_ACTIVE)
        false
    )
)

;; User status checker
(define-private (check-active-user (user principal))
    (match (map-get? Users user)
        user-data (and 
            (is-eq (get status user-data) STATUS_ACTIVE)
            (is-none (get deactivation-time user-data))
        )
        false
    )
)

;; User existence checker
(define-private (user-exists (user principal))
    (is-some (map-get? Users user))
)

;; Block status checker
(define-private (is-blocked (blocker principal) (blocked principal))
    (is-some (map-get? BlockedUsers {blocker: blocker, blocked: blocked}))
)

;; Privacy settings getter
(define-private (get-privacy-settings (user principal))
    (default-to
        {
            friend-list-visible: true,
            status-visible: true,
            metadata-visible: true,
            last-seen-visible: true,
            profile-image-visible: true,
            encryption-enabled: false,
            last-updated: stacks-block-height
        }
        (map-get? UserPrivacy user)
    )
)

;; Public Functions
;; ===============

;; Batch size optimizer
(define-public (optimize-batch-size (user principal))
    (let (
        (batch-data (unwrap-panic (map-get? UserBatches user)))
        (current-time stacks-block-height)
        (time-since-last-batch (- current-time (get last-batch-timestamp batch-data)))
        (current-batch-size (get batch-size batch-data))
        (items-in-current-batch (get current-batch-items batch-data))
    )
        (if (> time-since-last-batch BATCH_EXPIRY_PERIOD)
            (begin
                (map-set UserBatches user
                    (merge batch-data {
                        batch-size: (max-uint MIN_BATCH_SIZE (/ current-batch-size u2)),
                        current-batch-items: u0,
                        last-batch-timestamp: current-time
                    })
                )
                (ok true)
            )
            (begin
                (map-set UserBatches user
                    (merge batch-data {
                        batch-size: (min-uint MAX_BATCH_SIZE 
                            (if (>= items-in-current-batch (/ current-batch-size u2))
                                (* current-batch-size u2)
                                current-batch-size
                            ))
                    })
                )
                (ok true)
            )
        )
    )
)

;; Privacy settings updater
(define-public (update-advanced-privacy-settings
    (friend-list-visible bool)
    (status-visible bool)
    (metadata-visible bool)
    (last-seen-visible bool)
    (profile-image-visible bool)
    (encryption-enabled bool))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (check-active-user caller) ERR_DEACTIVATED)
        (asserts! (check-rate-limit caller u2) ERR_RATE_LIMITED)
        
        (map-set UserPrivacy
            caller
            {
                friend-list-visible: friend-list-visible,
                status-visible: status-visible,
                metadata-visible: metadata-visible,
                last-seen-visible: last-seen-visible,
                profile-image-visible: profile-image-visible,
                encryption-enabled: encryption-enabled,
                last-updated: stacks-block-height
            }
        )
        
        (update-rate-limit caller u2)
        (update-user-activity caller)
        
        (print {
            event: "privacy-updated",
            user: caller,
            timestamp: stacks-block-height
        })
        (ok true)
    )
)

;; Profile updater
(define-public (update-user-profile
    (name (optional (string-ascii 64)))
    (metadata (optional (string-utf8 256)))
    (encryption-key (optional (buff 32)))
    (profile-image (optional (string-utf8 256))))
    (let
        (
            (caller tx-sender)
            (user (unwrap-panic (map-get? Users caller)))
        )
        (asserts! (check-active-user caller) ERR_DEACTIVATED)
        (asserts! (check-rate-limit caller u2) ERR_RATE_LIMITED)
        
        (map-set Users caller
            (merge user {
                name: (default-to (get name user) name),
                metadata: (if (is-some metadata) metadata (get metadata user)),
                encryption-key: (if (is-some encryption-key) encryption-key (get encryption-key user)),
                profile-image: (if (is-some profile-image) profile-image (get profile-image user))
            })
        )
        
        (update-rate-limit caller u2)
        (update-user-activity caller)
        
        (print {
            event: "profile-updated",
            user: caller,
            timestamp: stacks-block-height
        })
        (ok true)
    )
)

;; Batch size setter
(define-public (set-batch-size (new-size uint))
    (let
        (
            (caller tx-sender)
            (batch-data (unwrap-panic (map-get? UserBatches caller)))
        )
        (asserts! (check-active-user caller) ERR_DEACTIVATED)
        (asserts! (and (>= new-size MIN_BATCH_SIZE) (<= new-size MAX_BATCH_SIZE)) ERR_INVALID_INPUT)
        
        (map-set UserBatches caller
            (merge batch-data {
                batch-size: new-size
            })
        )
        
        (print {
            event: "batch-size-updated",
            user: caller,
            new-size: new-size,
            timestamp: stacks-block-height
        })
        (ok true)
    )
)