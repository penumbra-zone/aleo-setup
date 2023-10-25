use std::convert::{From, TryFrom};

/// A marker type that captures the relationships between a domain type (`Self`) and a protobuf type (`Self::Proto`).
pub trait DomainType
where
    // Self: TypeUrl will be required once TypeUrl is implemented for all domain types.
    Self: TypeUrl + Clone + Sized + TryFrom<Self::Proto>,
    Self::Proto: prost::Message + Default + From<Self> + Send + Sync + 'static,
    anyhow::Error: From<<Self as TryFrom<Self::Proto>>::Error>,
{
    type Proto;

    /// Encode this domain type to a byte vector, via proto type `P`.
    fn encode_to_vec(&self) -> Vec<u8> {
        use prost::Message;
        self.to_proto().encode_to_vec()
    }

    /// Convert this domain type to the associated proto type.
    ///
    /// This uses the `From` impl internally, so it works exactly
    /// like `.into()`, but does not require type inference.
    fn to_proto(&self) -> Self::Proto {
        Self::Proto::from(self.clone())
    }

    /// Decode this domain type from a byte buffer, via proto type `P`.
    fn decode<B: bytes::Buf>(buf: B) -> anyhow::Result<Self> {
        <Self::Proto as prost::Message>::decode(buf)?
            .try_into()
            .map_err(Into::into)
    }
}

/// A type that can be encoded to a protobuf `Any` message.
pub trait TypeUrl {
    const TYPE_URL: &'static str;
}

