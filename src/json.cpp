#include "json.h"

#include <rapidjson/writer.h>

#include "utility.h"

namespace CapJSON
{
JSON::JSON(NetworkPacket& np)
{
    rapidjson::StringBuffer sb;
    rapidjson::Writer<rapidjson::StringBuffer> writer(sb);

    BuildJSON(np, writer);

    json_ = sb.GetString();
}

std::ostream& operator<<(std::ostream& out, const JSON& j)
{
    out << j.json_;
    return out ;
}
}
