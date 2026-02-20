//! Functions for parsing & serialization of Tachyon transaction components.

use core2::io::{self, Read, Write};
use pasta_curves::Fp;
use ff::PrimeField;

use zcash_tachyon as tachyon;
use zcash_encoding::{CompactSize, Vector};
use zcash_protocol::value::ZatBalance;

use crate::{
    encoding::{ReadBytesExt, WriteBytesExt}, 
    transaction::Transaction
};

/// Reads a [`tachyon::Bundle`] from a v6 transaction format.
pub fn read_v6_bundle<R: Read>(
    mut reader: R,
) -> io::Result<Option<tachyon::Bundle<ZatBalance>>> {
    let actions = Vector::read(&mut reader, |r| read_action(r))?;
    if actions.is_empty() {
        Ok(None)
    } else {
        let value_balance = Transaction::read_amount(&mut reader)?;
        let binding_sig = read_binding_signature(&mut reader)?;
        let stamp = read_stamp(&mut reader)?;

        Ok(Some(tachyon::Bundle {
            actions,
            value_balance,
            binding_sig,
            stamp,
        }))
    }
}

/// Writes a [`tachyon::Bundle`] in the v6 transaction format.
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&tachyon::Bundle<ZatBalance>>,
    mut writer: W,
) -> io::Result<()> {
    if let Some(bundle) = bundle {
        Vector::write(&mut writer, &bundle.actions, |w, a| write_action(w, a))?;
        writer.write_all(&bundle.value_balance.to_i64_le_bytes())?;
        write_binding_signature(&mut writer, &bundle.binding_sig)?;
        write_stamp(&mut writer, &bundle.stamp)?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }
    Ok(())
}

fn read_action<R: Read>(mut reader: R) -> io::Result<tachyon::Action> {
    let cv = read_value_commitment(&mut reader)?;
    let rk = read_randomized_verification_key(&mut reader)?;
    let sig = read_spend_auth_signature(&mut reader)?;

    Ok(tachyon::Action { cv, rk, sig })
}

fn write_action<W: Write>(mut writer: W, action: &tachyon::Action) -> io::Result<()> {
    write_value_commitment(&mut writer, &action.cv)?;
    write_randomized_verification_key(&mut writer, &action.rk)?;
    write_spend_auth_signature(&mut writer, &action.sig)?;
    Ok(())
}

fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<tachyon::value::Commitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    
    tachyon::value::Commitment::try_from(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tachyon value commitment"))
}

fn write_value_commitment<W: Write>(mut writer: W, cv: &tachyon::value::Commitment) -> io::Result<()> {
    let bytes: [u8; 32] = (*cv).into();
    writer.write_all(&bytes)
}

fn read_randomized_verification_key<R: Read>(mut reader: R) -> io::Result<tachyon::RandomizedVerificationKey> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    
    tachyon::RandomizedVerificationKey::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid randomized verification key"))
}

fn write_randomized_verification_key<W: Write>(mut writer: W, rk: &tachyon::RandomizedVerificationKey) -> io::Result<()> {
    let bytes: [u8; 32] = (*rk).into();
    writer.write_all(&bytes)
}

fn read_spend_auth_signature<R: Read>(mut reader: R) -> io::Result<tachyon::SpendAuthSignature> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(tachyon::SpendAuthSignature::from(bytes))
}

fn write_spend_auth_signature<W: Write>(mut writer: W, sig: &tachyon::SpendAuthSignature) -> io::Result<()> {
    writer.write_all(&<[u8; 64]>::from(*sig))
}

fn read_binding_signature<R: Read>(mut reader: R) -> io::Result<tachyon::BindingSignature> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(tachyon::BindingSignature::from(bytes))
}

fn write_binding_signature<W: Write>(mut writer: W, sig: &tachyon::BindingSignature) -> io::Result<()> {
    writer.write_all(&<[u8; 64]>::from(*sig))
}

fn read_stamp<R: Read>(mut reader: R) -> io::Result<Option<tachyon::Stamp>> {
    let has_stamp = reader.read_u8()?;
    if has_stamp == 0 {
        Ok(None)
    } else {
        let tachygrams = Vector::read(&mut reader, |r| read_tachygram(r))?;
        let anchor = read_anchor(&mut reader)?;
        let proof = read_proof(&mut reader)?;
        
        Ok(Some(tachyon::Stamp {
            tachygrams,
            anchor,
            proof,
        }))
    }
}

fn write_stamp<W: Write>(mut writer: W, stamp: &Option<tachyon::Stamp>) -> io::Result<()> {
    if let Some(stamp) = stamp {
        writer.write_u8(1)?; // has_stamp = true
        Vector::write(&mut writer, &stamp.tachygrams, |w, t| write_tachygram(w, t))?;
        write_anchor(&mut writer, &stamp.anchor)?;
        write_proof(&mut writer, &stamp.proof)?;
    } else {
        writer.write_u8(0)?; // has_stamp = false
    }
    Ok(())
}

fn read_tachygram<R: Read>(mut reader: R) -> io::Result<tachyon::Tachygram> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    
    // Convert bytes to Fp, then to Tachygram
    let fp = Fp::from_repr(bytes).into_option().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid field element for tachygram")
    })?;
    Ok(tachyon::Tachygram::from(fp))
}

fn write_tachygram<W: Write>(mut writer: W, tachygram: &tachyon::Tachygram) -> io::Result<()> {
    let fp: Fp = (*tachygram).into();
    writer.write_all(&fp.to_repr())
}

fn read_anchor<R: Read>(mut reader: R) -> io::Result<tachyon::Anchor> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    
    // Convert bytes to Fp, then to Anchor
    let fp = Fp::from_repr(bytes).into_option().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid field element for anchor")
    })?;
    Ok(tachyon::Anchor::from(fp))
}

fn write_anchor<W: Write>(mut writer: W, anchor: &tachyon::Anchor) -> io::Result<()> {
    let fp: Fp = (*anchor).into();
    writer.write_all(&fp.to_repr())
}

fn read_proof<R: Read>(mut reader: R) -> io::Result<tachyon::Proof> {
    // Read the fixed-size proof bytes (192 bytes)
    let mut proof_bytes = [0u8; 192];
    reader.read_exact(&mut proof_bytes)?;
    
    tachyon::Proof::try_from(&proof_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tachyon proof"))
}

fn write_proof<W: Write>(mut writer: W, proof: &tachyon::Proof) -> io::Result<()> {
    let proof_bytes: [u8; 192] = (*proof).into();
    writer.write_all(&proof_bytes)
}

pub trait MapAuth<A, B> {
    fn map_authorization(&self, a: A) -> B;
}

/// The identity map.
impl MapAuth<ZatBalance, ZatBalance> for () {
    fn map_authorization(&self, a: ZatBalance) -> ZatBalance {
        a
    }
}