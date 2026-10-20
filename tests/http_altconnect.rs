use rust_xmpp::{config::Config, http_altconnect::links, http_config::HttpConfig};
use serde_json::json;
fn config(global: serde_json::Value, local: serde_json::Value) -> Config {
    serde_json::from_value(json!({"global":global,"hosts":{"xmpp.test":{"options":local}}}))
        .unwrap()
}
#[test]
fn native_link_order_schemes_and_loaded_module_gates() {
    let mut c = config(
        json!({"modules_enabled":["http_altconnect","bosh","websocket"]}),
        json!({}),
    );
    let all = links(&c, "xmpp.test", true, 5281).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].rel, "urn:xmpp:alt-connections:xbosh");
    assert_eq!(all[0].href, "https://xmpp.test:5281/http-bind");
    assert_eq!(all[1].rel, "urn:xmpp:alt-connections:websocket");
    assert_eq!(all[1].href, "wss://xmpp.test:5281/xmpp-websocket");
    c.hosts
        .get_mut("xmpp.test")
        .unwrap()
        .options
        .insert("advertise_bosh".into(), json!(false));
    assert_eq!(
        links(&c, "xmpp.test", false, 80).unwrap()[0].href,
        "ws://xmpp.test/xmpp-websocket"
    );
    c.global
        .insert("modules_disabled".into(), json!(["websocket"]));
    assert!(links(&c, "xmpp.test", true, 443).unwrap().is_empty());
}
#[test]
fn public_prefix_and_host_paths_inherit_independently() {
    let c = config(
        json!({"modules_enabled":["http_altconnect","bosh","websocket"],"http_host":"web.test","http_external_url":"https://global.test/base","http_paths":{"bosh":"/bind-$host","altconnect":"/discover-$host"}}),
        json!({"http_external_url":"https://proxy.test:443/public/","http_paths":{"websocket":"/ws"}}),
    );
    let all = links(&c, "xmpp.test", false, 5280).unwrap();
    assert_eq!(all[0].href, "https://proxy.test/public/bind-xmpp.test");
    assert_eq!(all[1].href, "wss://proxy.test/public/ws");
    assert_eq!(
        HttpConfig::for_host(&c, "xmpp.test")
            .unwrap()
            .altconnect_path,
        "/discover-xmpp.test"
    );
}
#[test]
fn bad_advertisement_types_and_route_collisions_are_rejected() {
    let c = config(json!({"advertise_websocket":"yes"}), json!({}));
    assert!(c.validate().is_err());
    assert!(links(&c, "xmpp.test", false, 5280).is_err());
    for module in ["bosh", "websocket"] {
        for path in ["/.well-known/host-meta", "/.well-known/host-meta.json/"] {
            let c = config(
                json!({"modules_enabled":["http_altconnect",module],"http_paths":{module:path}}),
                json!({}),
            );
            assert!(c.validate().is_err());
        }
    }
}
