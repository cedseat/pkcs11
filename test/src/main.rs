extern crate libc;
extern crate libloading;
extern crate pkcs11_sys;
extern crate pkcs11;

use pkcs11::cryptoki::Cryptoki;
use pkcs11::cryptoki::types::UserType;
use pkcs11::cryptoki::types::ObjectHandle;
use pkcs11::cryptoki::types::AttributeType;
use pkcs11_sys as sys;
use pkcs11::cryptoki::structs::Attribute;
use pkcs11::cryptoki::structs::SlotInfo;
use pkcs11::cryptoki::structs::TokenInfo;
use pkcs11::cryptoki::flags::SessionFlags;

fn main() {

    let ck:Cryptoki = Cryptoki::load("/usr/local/galss/libcps3_pkcs11_lux.so").unwrap();
    //let ck:Cryptoki = Cryptoki::load("C:\\Windows\\System32\\cps3_pkcs11_w64.dll").unwrap();
    let info = ck.get_slot_list(true);
    println!("info {:?}", info);
    let list_slot = info.unwrap();
    for slot in list_slot {
        let mut slot_info = SlotInfo::default();
        let result = ck.get_slot_info(slot, &mut slot_info);
        println!("slot_info.slot_description {:?}", slot_info.slot_description());
        println!("slot_info.manufacturer_id {:?}", slot_info.manufacturer_id());
        println!("slot_info.hardware_version {:?}", slot_info.hardware_version());
        println!("slot_info.firmware_version {:?}", slot_info.firmware_version());

        let mut token = TokenInfo::default();
        let result = ck.get_token_info(slot, &mut token);
        println!("token.label {:?}", token.label());
        println!("token.manufacturer {:?}", token.manufacturer());
        println!("token.model {:?}", token.model());
        println!("token.serial_number {:?}", token.serial_number());
    }
    let info = ck.get_slot_list(true);
    let slot = info.unwrap()[0];

    let session = ck.open_session(slot, SessionFlags::from(sys::CKF_HW)).unwrap();

    let login_res = ck.login(session, UserType::from(sys::CKU_USER), Some("1234"));


    println!("login_res {:?}", login_res);

    let keyClass:sys::CK_ATTRIBUTE_TYPE = sys::CKO_CERTIFICATE;
    let keyClass1:sys::CK_CERTIFICATE_TYPE = sys::CKC_X_509;

    let templates:Vec<Attribute> = vec![
                                        Attribute::from_ref(AttributeType::from(sys::CKA_CLASS), &keyClass),
                                        Attribute::from_ref(AttributeType::from(sys::CKA_CERTIFICATE_TYPE), &keyClass1)
                                    ];
    let find_objects_init_result = ck.find_objects_init(session, templates.as_slice());

    println!("find_objects_init_result {:?}", find_objects_init_result);

    let oh = ObjectHandle::default();
    let mut res:Vec<ObjectHandle> = vec![oh];
    let find_objects_result = ck.find_objects(session, res.as_mut_slice());

    println!("find_objects_result {:?}", find_objects_result);


    let mut vec_label = Vec::new();
    vec_label.resize(100, 0);
    let mut vec_id = Vec::new();
    vec_id.resize(100, 0);
    let mut vec_subject = Vec::new();
    vec_subject.resize(300, 0);
    let mut vec_value = Vec::new();
    vec_value.resize(2048, 0);

    let mut templates:Vec<Attribute> = vec![
                                    Attribute::from_bytes(AttributeType::from(sys::CKA_LABEL), vec_label.as_mut_slice()),
                                    Attribute::from_bytes(AttributeType::from(sys::CKA_ID), vec_id.as_mut_slice()),
                                    Attribute::from_bytes(AttributeType::from(sys::CKA_SUBJECT), vec_subject.as_mut_slice()),
                                    Attribute::from_bytes(AttributeType::from(sys::CKA_VALUE), vec_value.as_mut_slice()),
                                    ];

    let result = ck.get_attribute_value(session, res[0], templates.as_mut_slice());

    println!("result {:?}", result);

    for template in templates {
        println!("template.bytes {:?}", template.bytes());
        let value = match template.bytes() {
            Some(bytes) => String::from_utf8_lossy(template.bytes().unwrap()).into_owned(),
            None => "empty".to_string()
        };
        println!("template.value {:?}", value);

    }
}