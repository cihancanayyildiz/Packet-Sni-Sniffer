use bpaf::Bpaf;

#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments{
    #[bpaf(long, short)]
    /// Enter the capture type(Online or Offline)
    pub capture_type: String,
    #[bpaf(long, short)]
    /// If it is online capturing then enter the connection(eth0,wls03 etc), if it is offline then enter the pcap path.
    pub input: String,
}

