// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Types are based on "Architecture Specification: Intel Trust Domain Extensions
// Module 1.0", Feb 2023, Section 22.6

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct ReportType {
    pub r#type: u8,
    pub subtype: u8,
    pub version: u8,
    pub _reserved: u8,
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct ReportMac {
    pub reporttype: ReportType,
    pub _reserved_1: [u8; 12],
    pub cpusvn: [u8; 16],
    pub tee_tcb_info_hash: [u8; 48],
    pub tee_info_hash: [u8; 48],
    pub reportdata: [u8; 64],
    pub _reserved_2: [u8; 32],
    pub mac: [u8; 32],
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct Rtmr {
    pub register_data: [u8; 48],
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct TdInfo {
    pub attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr: [Rtmr; 4],
    pub _reserved: [u8; 112],
}

#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, Copy, Clone, Debug, PartialEq)]
pub struct TdReport {
    pub report_mac: ReportMac,
    pub tee_tcb_info: [u8; 239],
    pub _reserved: [u8; 17],
    pub tdinfo: TdInfo,
}
