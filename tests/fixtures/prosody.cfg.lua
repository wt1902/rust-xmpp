-- ============================================================================
-- БАЗОВАЯ КОНФИГУРАЦИЯ PROSODY для wthome.ru
-- ============================================================================

-- Данные сервера
data_path = "/var/lib/prosody"

-- Администраторы
admins = { "wt@wthome.ru" }

external_addresses = { "88.204.18.107" }

-- Плагины (модули)
modules_enabled = {
    -- Обязательные модули
    "roster";           -- Список контактов
    "saslauth";         -- Аутентификация
    "tls";              -- Шифрование TLS
    "disco";            -- Service Discovery (нужен для OMEMO)
    --"posix";            -- POSIX функции
    
    -- OMEMO и современные клиенты
    "pep_simple";              -- Personal Eventing Protocol (ОБЯЗАТЕЛЬНО для OMEMO!)
    "private";          -- Приватное хранилище
   -- "vcard";            -- Визитные карточки
    "pep";
    "vcard_legacy";
    --"pep_vcard_avatar";
    --"pubsub";           -- Publish-Subscribe
    
    -- Синхронизация и история
    "carbons";          -- Message Carbons (синхронизация между устройствами)
    "mam";              -- Message Archive Management (история сообщений)
    "smacks";           -- Stream Management (для мобильных клиентов)
    "csi_simple";       -- Client State Indication (оптимизация для мобильных)
    
    -- Звонки (Jingle)
    "turn_external";    -- Внешний TURN сервер для звонков
    
    -- Дополнительные возможности
    "register";         -- Регистрация аккаунтов
    "blocklist";        -- Блокировка контактов
    "bookmarks";         -- Закладки для конференций
    "ping";             -- Keep-alive
    "time";             -- Время сервера
    "version";          -- Версия сервера
    "uptime";           -- Время работы сервера
    
    -- Web-клиенты
    "websocket";        -- WebSocket для веб-клиентов
    "bosh";             -- BOSH (устаревший, но для совместимости)
    
    -- Файлы и медиа
    --"http_file_share";  -- HTTP File Sharing (XEP-0363)
    --"http_upload";      -- HTTP Upload (альтернатива)
    "admin_shell";
    "cloud_notify";
   -- "s2s_auth_dane";
    "s2s";
    "s2s_auth_certs";
    "seclabels";
    "sasl_ssdp";
    "sasl2";
   -- "admin_web";
}

-- ============================================================================
-- ЛОГИРОВАНИЕ
-- ============================================================================

log = {
    info = "*console";
    error = "*console";
    -- "*syslog";  -- Раскомментировать для syslog
}

-- ============================================================================
-- ДОПОЛНИТЕЛЬНЫЕ НАСТРОЙКИ БЕЗОПАСНОСТИ
-- ============================================================================

-- Rate limiting
limits = {
    c2s = {
        rate = "100kb/s";
    };
    s2sin = {
        rate = "300kb/s";
    };
}

security_labels = {
	default_policy = "default";
	policies = {
		["default"] = {
			classifications = {
                		{ name = "Unclassified", default = true },
		                { name = "Confidential" },
		                { name = "Secret" },
		                { name = "Top Secret" }
	            	};
		};
	};
}

vcard_avatar = {
	sync_to_vcard = true;
	sync_to_pep = true;
}

-- Отключаем ненужное
--modules_disabled = {
--    "s2s";              -- Отключить федерацию (убрать если нужна связь с другими серверами)
--}

smacks_max_unacked = 100
smacks_hibernation_time = 300
allow_unencrypted_plain_auth = false

push_notification_with_body = true
push_notification_with_sender = true
push_notification_important_body = "New message"
push_max_devices = 50
push_max_errors = 32
push_max_hibernation_timeout = 259200

-- Аутентификация
allow_registration = true  -- Отключить публичную регистрацию (безопасность)

-- TLS настройки
c2s_require_encryption = true
s2s_require_encryption = true
s2s_secure_auth = true

-- Порты
interfaces = { "0.0.0.0", "::" }
c2s_ports = { 5222 }
s2s_ports = { 5269 }
http_ports = { 5280 }
https_ports = { 5281 }

-- HTTP интерфейсы для файлов и BOSH
http_interfaces = { "*" }
https_interfaces = { "*" }

-- BOSH/WebSocket настройки
consider_bosh_secure = true
consider_websocket_secure = true
--cross_domain_bosh = true
--cross_domain_websocket = true

http_cors_override = {
	bosh = {
		enabled = true;
		origins = {
			"https://wthome.ru";
		};
	};
	websocket = {
		enabled = true;
		origins = {
			"https://wthome.ru";
		};
	};
}

-- ============================================================================
-- НАСТРОЙКА ЗВОНКОВ (TURN/STUN)
-- ============================================================================

-- Настройка внешнего TURN сервера для Jingle звонков
turn_external_host = "turn.wthome.ru"  -- или IP сервера
turn_external_port = 3478
turn_external_secret = "TEST-ONLY-NOT-A-REAL-SECRET"
turn_external_ttl = 86400

-- Альтернативно: если coturn на том же сервере
-- turn_external_host = "wthome.ru"

-- ============================================================================
-- НАСТРОЙКА OMEMO (через PEP)
-- ============================================================================

-- PEP настройки для OMEMO
pep_max_items = 10000

-- OMEMO работает через PEP автоматически при включенном mod_pep
-- Никаких дополнительных настроек не требуется!

-- ============================================================================
-- MAM (История сообщений)
-- ============================================================================

archive_expires_after = "never"  -- never delete history archive
default_archive_policy = true  -- Включить архивирование по умолчанию

-- ============================================================================
-- HTTP File Share (отправка файлов)
-- ============================================================================

-- Настройка компонента для файлов (см. ниже в VirtualHost)
--http_file_share_expires_after = 7 * 24 * 60 * 60  -- 7 дней
--http_file_share_global_quota = 1024 * 1024 * 1024 * 10  -- 10 GB

-- ============================================================================
-- ВИРТУАЛЬНЫЙ ХОСТ
-- ============================================================================

VirtualHost "wthome.ru"
    authentication = "internal_hashed"
    -- SSL сертификаты (Let's Encrypt или самоподписанные)
    ssl = {
        key = "/etc/prosody/certs/privkey.pem";
        certificate = "/etc/prosody/certs/fullchain.pem";
    }
    
    -- Дополнительные модули для этого домена
    modules_enabled = {
        "mam";  -- Убедимся что MAM включен
    }

-- ============================================================================
-- КОМПОНЕНТЫ
-- ============================================================================

-- Конференции (MUC)
Component "conference.wthome.ru" "muc"
    name = "Conference Rooms"
    restrict_room_creation = "local"  -- Только локальные пользователи создают комнаты
    max_history_messages = 100
    muc_tombstones = true
    
    -- MAM для конференций (групповой чат)
    modules_enabled = { 
--	    "mam";
	    "muc_mam";
    }
    mam_muc_archive_expires_after = "1w"

-- Обмен файлами
Component "upload.wthome.ru" "http_file_share"
    name = "File Sharing"
    http_file_share_expires_after = "never"  -- 7 дней
    http_file_share_global_quota = 1024 * 1024 * 1024 * 100  -- 100 GB
    http_file_share_size_limit = 1024 * 1024 * 1024 * 10 -- 10 GB

-- PubSub (для OMEMO и других фич)
Component "pubsub.wthome.ru" "pubsub"
    name = "PubSub Service"
    restrict_node_creation = false

-- Отключаем устаревшие методы аутентификации
-- disable_sasl_mechanisms = { "DIGEST-MD5", "PLAIN" } -- , "SCRAM-SHA-1" }
