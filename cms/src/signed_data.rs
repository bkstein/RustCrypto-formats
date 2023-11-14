//! SignedData-related types

use crate::cert::{CertificateChoices, IssuerAndSerialNumber};
use crate::content_info::CmsVersion;
use crate::revocation::RevocationInfoChoices;

use core::cmp::Ordering;
use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Choice, DerOrd, Sequence, ValueOrd};
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::Attributes;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::impl_newtype;

/// The `SignedData` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignedData ::= SEQUENCE {
///       version CMSVersion,
///       digestAlgorithms SET OF DigestAlgorithmIdentifier,
///       encapContentInfo EncapsulatedContentInfo,
///       certificates [0] IMPLICIT CertificateSet OPTIONAL,
///       crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///       signerInfos SignerInfos }
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
// TODO(bk) revert after debugging #[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub encap_content_info: EncapsulatedContentInfo,
    //todo consider defer decoding certs and CRLs
    // TODO(bk) revert after debugging #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub certificates: Option<CertificateSet>,
    // TODO(bk) revert after debugging #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub crls: Option<RevocationInfoChoices>,
    pub signer_infos: SignerInfos,
}

// TODO(bk) revert after debugging
impl<'__der_lifetime> ::der::DecodeValue<'__der_lifetime> for SignedData {
    fn decode_value<R: ::der::Reader<'__der_lifetime>>(
        reader: &mut R,
        header: ::der::Header,
    ) -> ::der::Result<Self> {
        use ::der::Reader as _;
        let length = if header.length.is_definite() {
            header.length.try_into()?
        } else {
            reader.indefinite_value_length()?
        };
        reader
            .read_nested(
                length,
                |reader| {
                    let version = reader.decode()?;
                    let digest_algorithms = reader.decode()?;
                    let encap_content_info = reader.decode()?;
                    let certificates = ::der::asn1::ContextSpecific::decode_implicit(
                        reader,
                        ::der::TagNumber::N0,
                    )?
                        .map(|cs| cs.value);
                    let crls = ::der::asn1::ContextSpecific::decode_implicit(
                        reader,
                        ::der::TagNumber::N1,
                    )?
                        .map(|cs| cs.value);
                    let signer_infos = reader.decode()?;
                    Ok(Self {
                        version,
                        digest_algorithms,
                        encap_content_info,
                        certificates,
                        crls,
                        signer_infos,
                    })
                },
            )
    }
}
impl ::der::EncodeValue for SignedData {
    fn value_len(&self) -> ::der::Result<::der::Length> {
        use ::der::Encode as _;
        [
            self.version.encoded_len()?,
            self.digest_algorithms.encoded_len()?,
            self.encap_content_info.encoded_len()?,
            self
                .certificates
                .as_ref()
                .map(|field| {
                    ::der::asn1::ContextSpecificRef {
                        tag_number: ::der::TagNumber::N0,
                        tag_mode: ::der::TagMode::Implicit,
                        value: field,
                    }
                })
                .encoded_len()?,
            self
                .crls
                .as_ref()
                .map(|field| {
                    ::der::asn1::ContextSpecificRef {
                        tag_number: ::der::TagNumber::N1,
                        tag_mode: ::der::TagMode::Implicit,
                        value: field,
                    }
                })
                .encoded_len()?,
            self.signer_infos.encoded_len()?,
        ]
            .into_iter()
            .try_fold(::der::Length::ZERO, |acc, len| acc + len)
    }
    fn encode_value(&self, writer: &mut impl ::der::Writer) -> ::der::Result<()> {
        use ::der::Encode as _;
        self.version.encode(writer)?;
        self.digest_algorithms.encode(writer)?;
        self.encap_content_info.encode(writer)?;
        self.certificates
            .as_ref()
            .map(|field| {
                ::der::asn1::ContextSpecificRef {
                    tag_number: ::der::TagNumber::N0,
                    tag_mode: ::der::TagMode::Implicit,
                    value: field,
                }
            })
            .encode(writer)?;
        self.crls
            .as_ref()
            .map(|field| {
                ::der::asn1::ContextSpecificRef {
                    tag_number: ::der::TagNumber::N1,
                    tag_mode: ::der::TagMode::Implicit,
                    value: field,
                }
            })
            .encode(writer)?;
        self.signer_infos.encode(writer)?;
        Ok(())
    }
}
impl<'__der_lifetime> ::der::Sequence<'__der_lifetime> for SignedData {}


/// The `DigestAlgorithmIdentifiers` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
///
/// [RFC 5652 Section 5.1]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
pub type DigestAlgorithmIdentifiers = SetOfVec<AlgorithmIdentifierOwned>;

/// CertificateSet structure as defined in [RFC 5652 Section 10.2.3].
///
/// ```text
///   CertificateSet ::= SET OF CertificateChoices
/// ```
///
/// [RFC 5652 Section 10.2.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-10.2.3
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CertificateSet(pub SetOfVec<CertificateChoices>);
impl_newtype!(CertificateSet, SetOfVec<CertificateChoices>);

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<CertificateChoices>> for CertificateSet {
    type Error = der::Error;

    fn try_from(vec: std::vec::Vec<CertificateChoices>) -> der::Result<CertificateSet> {
        Ok(CertificateSet(SetOfVec::try_from(vec)?))
    }
}

/// The `SignerInfos` type is defined in [RFC 5652 Section 5.1].
///
/// ```text
///   SignerInfos ::= SET OF SignerInfo
/// ```
///
/// [RFC 5652 Section 5.1]: https://www.rfc-editor.org/rfc/rfc5652#section-5.1
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SignerInfos(pub SetOfVec<SignerInfo>);
impl_newtype!(SignerInfos, SetOfVec<SignerInfo>);

#[cfg(feature = "std")]
impl TryFrom<std::vec::Vec<SignerInfo>> for SignerInfos {
    type Error = der::Error;

    fn try_from(vec: std::vec::Vec<SignerInfo>) -> der::Result<SignerInfos> {
        Ok(SignerInfos(SetOfVec::try_from(vec)?))
    }
}

/// The `EncapsulatedContentInfo` type is defined in [RFC 5652 Section 5.2].
///
/// ```text
///   EncapsulatedContentInfo ::= SEQUENCE {
///       eContentType       CONTENT-TYPE.&id({ContentSet}),
///       eContent           [0] EXPLICIT OCTET STRING
///               ( CONTAINING CONTENT-TYPE.
///                   &Type({ContentSet}{@eContentType})) OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.2]: https://www.rfc-editor.org/rfc/rfc5652#section-5.2
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
#[allow(missing_docs)]
pub struct EncapsulatedContentInfo {
    pub econtent_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub econtent: Option<Any>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignerInfo ::= SEQUENCE {
///       version CMSVersion,
///       sid SignerIdentifier,
///       digestAlgorithm DigestAlgorithmIdentifier,
///       signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///       signatureAlgorithm SignatureAlgorithmIdentifier,
///       signature SignatureValue,
///       unsignedAttrs [1] IMPLICIT Attributes
///           {{UnsignedAttributes}} OPTIONAL }
/// ```
///
/// [RFC 5652 Section 5.3]: https://www.rfc-editor.org/rfc/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Sequence, ValueOrd)]
#[allow(missing_docs)]
pub struct SignerInfo {
    pub version: CmsVersion,
    pub sid: SignerIdentifier,
    pub digest_alg: AlgorithmIdentifierOwned,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub signed_attrs: Option<SignedAttributes>,
    pub signature_algorithm: AlgorithmIdentifierOwned,
    pub signature: SignatureValue,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    pub unsigned_attrs: Option<UnsignedAttributes>,
}

/// The `SignerInfo` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub type SignedAttributes = Attributes;

/// The `SignerIdentifier` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier \[0\] SubjectKeyIdentifier }
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
#[derive(Clone, Debug, Eq, PartialEq, Choice)]
#[allow(missing_docs)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),

    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

// TODO DEFER ValueOrd is not supported for CHOICE types (see new_enum in value_ord.rs)
impl ValueOrd for SignerIdentifier {
    fn value_cmp(&self, other: &Self) -> der::Result<Ordering> {
        use der::Encode;
        self.to_der()?.der_cmp(&other.to_der()?)
    }
}

/// The `UnsignedAttributes` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub type UnsignedAttributes = Attributes;

/// The `SignatureValue` type is defined in [RFC 5652 Section 5.3].
///
/// ```text
///   SignatureValue ::= OCTET STRING
/// ```
///
/// [RFC 5652 Section 5.3]: https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
pub type SignatureValue = OctetString;
