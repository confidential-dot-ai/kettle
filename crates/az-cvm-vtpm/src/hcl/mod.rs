// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tdx::TdReport;
use jsonwebkey::JsonWebKey;
use memoffset::offset_of;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport as SnpReport;
use sev::parser::ByteParser;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::mem::size_of;
use std::ops::Range;
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes};

const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
const TD_REPORT_SIZE: usize = size_of::<TdReport>();
// SNP AttestationReport binary format size as defined in AMD SNP Firmware ABI specification.
// This corresponds to ATT_REP_FW_LEN defined in sev-6.x crate's snp.rs (which is not public).
// All SNP report versions (v2, v3-PreTurin, v3-Turin) use this fixed size.
pub const SNP_REPORT_SIZE: usize = 1184;
const fn max(a: usize, b: usize) -> usize {
    if a > b {
        return a;
    }
    b
}
const MAX_REPORT_SIZE: usize = max(SNP_REPORT_SIZE, TD_REPORT_SIZE);
const SNP_REPORT_TYPE: u32 = 2;
const TDX_REPORT_TYPE: u32 = 4;
const HW_REPORT_OFFSET: usize = offset_of!(AttestationReport, hw_report);
const fn report_range(report_size: usize) -> Range<usize> {
    HW_REPORT_OFFSET..(HW_REPORT_OFFSET + report_size)
}
const TD_REPORT_RANGE: Range<usize> = report_range(TD_REPORT_SIZE);
const SNP_REPORT_RANGE: Range<usize> = report_range(SNP_REPORT_SIZE);

#[derive(Error, Debug)]
pub enum HclError {
    #[error("invalid report size")]
    InvalidReportSize,
    #[error("invalid report type")]
    InvalidReportType,
    #[error("AkPub not found")]
    AkPubNotFound,
    #[error("JSON parse error")]
    JsonParseError(#[from] serde_json::Error),
}

#[derive(Deserialize, Debug)]
struct VarDataKeys {
    keys: Vec<JsonWebKey>,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
enum IgvmHashType {
    Invalid = 0,
    Sha256,
    Sha384,
    Sha512,
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromBytes, Immutable, IntoBytes)]
struct IgvmRequestData {
    data_size: u32,
    version: u32,
    report_type: u32,
    report_data_hash_type: u32,
    variable_data_size: u32,
    variable_data: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromBytes, Immutable, IntoBytes)]
struct AttestationHeader {
    signature: u32,
    version: u32,
    report_size: u32,
    request_type: u32,
    status: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Debug, PartialEq, FromBytes, Immutable, IntoBytes)]
struct AttestationReport {
    header: AttestationHeader,
    hw_report: [u8; MAX_REPORT_SIZE],
    hcl_data: IgvmRequestData,
}

pub struct HclReport {
    bytes: Vec<u8>,
    attestation_report: AttestationReport,
    report_type: ReportType,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReportType {
    Tdx,
    Snp,
}

#[allow(clippy::large_enum_variant)]
pub enum HwReport {
    Tdx(TdReport),
    Snp(SnpReport),
}

impl HclReport {
    /// Parse a HCL report from a byte slice.
    pub fn new(bytes: Vec<u8>) -> Result<Self, HclError> {
        const STRUCT_SIZE: usize = std::mem::size_of::<AttestationReport>();

        if bytes.len() < STRUCT_SIZE {
            return Err(HclError::InvalidReportSize);
        }

        // Read fixed struct using zerocopy
        let struct_bytes = &bytes[..STRUCT_SIZE];
        let cursor = struct_bytes;
        let attestation_report =
            AttestationReport::read_from_bytes(cursor).map_err(|_| HclError::InvalidReportSize)?;

        // Validate variable data size if present
        let var_data_size = attestation_report.hcl_data.variable_data_size as usize;
        if var_data_size > 0 {
            let var_data_end = STRUCT_SIZE + var_data_size;
            if bytes.len() < var_data_end {
                return Err(HclError::InvalidReportSize);
            }
        }

        let report_type = match attestation_report.hcl_data.report_type {
            TDX_REPORT_TYPE => ReportType::Tdx,
            SNP_REPORT_TYPE => ReportType::Snp,
            _ => return Err(HclError::InvalidReportType),
        };

        let report = Self {
            bytes,
            attestation_report,
            report_type,
        };
        Ok(report)
    }

    /// Get the type of the nested hardware report
    pub fn report_type(&self) -> ReportType {
        self.report_type
    }

    fn report_slice(&self) -> &[u8] {
        match self.report_type {
            ReportType::Tdx => self.bytes[TD_REPORT_RANGE].as_ref(),
            ReportType::Snp => self.bytes[SNP_REPORT_RANGE].as_ref(),
        }
    }

    /// Get the SHA256 hash of the VarData section
    pub fn var_data_sha256(&self) -> [u8; 32] {
        if self.attestation_report.hcl_data.report_data_hash_type != IgvmHashType::Sha256 as u32 {
            unimplemented!(
                "Only SHA256 is supported, got hash type {}",
                self.attestation_report.hcl_data.report_data_hash_type
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(self.var_data());
        hasher.finalize().into()
    }

    /// Get the slice of the VarData section
    pub fn var_data(&self) -> &[u8] {
        let var_data_offset =
            offset_of!(AttestationReport, hcl_data) + offset_of!(IgvmRequestData, variable_data);
        let hcl_data = &self.attestation_report.hcl_data;
        let var_data_end = var_data_offset + hcl_data.variable_data_size as usize;
        &self.bytes[var_data_offset..var_data_end]
    }

    /// Get the vTPM's AKpub from the VarData section
    pub fn ak_pub(&self) -> Result<JsonWebKey, HclError> {
        let VarDataKeys { keys } = serde_json::from_slice(self.var_data())?;
        let ak_pub = keys
            .into_iter()
            .find(|key| {
                let Some(ref key_id) = key.key_id else {
                    return false;
                };
                key_id == HCL_AKPUB_KEY_ID
            })
            .ok_or(HclError::AkPubNotFound)?;
        Ok(ak_pub)
    }
}

impl TryFrom<&HclReport> for TdReport {
    type Error = HclError;

    fn try_from(hcl_report: &HclReport) -> Result<Self, Self::Error> {
        if hcl_report.report_type != ReportType::Tdx {
            return Err(HclError::InvalidReportType);
        }
        let bytes = hcl_report.report_slice();
        // Use zerocopy for safe casting - read_from_bytes consumes the bytes and handles large arrays
        let cursor = bytes;
        let td_report =
            TdReport::read_from_bytes(cursor).map_err(|_| HclError::InvalidReportSize)?;
        Ok(td_report)
    }
}

impl TryFrom<HclReport> for TdReport {
    type Error = HclError;

    fn try_from(hcl_report: HclReport) -> Result<Self, Self::Error> {
        (&hcl_report).try_into()
    }
}

impl TryFrom<&HclReport> for SnpReport {
    type Error = HclError;

    fn try_from(hcl_report: &HclReport) -> Result<Self, Self::Error> {
        if hcl_report.report_type != ReportType::Snp {
            return Err(HclError::InvalidReportType);
        }
        let bytes = hcl_report.report_slice();
        // Use the sev-6.x crate's from_bytes method which handles dynamic parsing
        // of different SNP report versions (v2, v3-PreTurin, v3-Turin)
        let snp_report = SnpReport::from_bytes(bytes).map_err(|_e| HclError::InvalidReportType)?;
        Ok(snp_report)
    }
}

impl TryFrom<HclReport> for SnpReport {
    type Error = HclError;

    fn try_from(hcl_report: HclReport) -> Result<Self, Self::Error> {
        (&hcl_report).try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hcl_report() {
        let bytes: &[u8] = include_bytes!("../../test/hcl-report-snp.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let _ = hcl_report.ak_pub().unwrap();

        let bytes: &[u8] = include_bytes!("../../test/hcl-report-tdx.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let _ = hcl_report.ak_pub().unwrap();
    }
}
