import register
import update
import transfer
import revoke

SERIALIZE_FIELDS = {
    "NAME_REGISTER": register.FIELDS,
    "NAME_UPDATE": update.FIELDS,
    "NAME_TRANSFER": transfer.FIELDS,
    "NAME_REVOKE": revoke.FIELDS
}