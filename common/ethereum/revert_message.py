from common.ethereum.errors import EthError


def decode(data: str) -> str | None:
    if not data:
        return None

    if (data_len := len(data)) < 8:
        raise EthError(
            code=3,
            message=f"Too less bytes to decode revert signature: {data_len}",
            data=data,
        )

    if data[:8] == "4e487b71":  # keccak256("Panic(uint256)")
        if len(data) < 8 + 64:
            raise EthError(
                code=3,
                message=f"Too less bytes to decode revert msg offset: {data_len}",
            )

        code = int(data[8 : 8 + 64], 16)
        return "Panic(" + str(code) + ")"

    if data[:8] != "08c379a0":  # keccak256("Error(string)")
        # _LOG.debug(f"failed to decode revert_message, unknown revert signature: {data[:8]}")
        return None

    if data_len < 8 + 64:
        raise EthError(
            code=3,
            message=f"Too less bytes to decode revert msg offset: {data_len}",
            data=data,
        )
    offset = int(data[8 : 8 + 64], 16) * 2

    if data_len < 8 + offset + 64:
        raise EthError(
            code=3,
            message=f"Too less bytes to decode revert msg len: {data_len}",
            data=data,
        )
    length = int(data[8 + offset : 8 + offset + 64], 16) * 2

    if data_len < 8 + offset + 64 + length:
        raise EthError(
            code=3,
            message=f"Too less bytes to decode revert msg: {data_len}",
            data=data,
        )

    message = str(bytes.fromhex(data[8 + offset + 64 : 8 + offset + 64 + length]), "utf8")
    return message
