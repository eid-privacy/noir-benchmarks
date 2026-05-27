/// Maximum raw payload length in bytes
/// Adjust this based on your expected JWT payload size.
/// NOTE: This experiment uses a full credential with complete portrait data,
/// resulting in a much larger payload than experiment40.
pub global PAYLOAD_MAX_LEN: u32 = 15000;
