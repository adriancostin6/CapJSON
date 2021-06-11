#ifndef CAPJSON_UTILITY_H
#define CAPJSON_UTILITY_H

#include <rapidjson/writer.h>

using rapidjson::Writer;
using rapidjson::StringBuffer;

namespace CapJSON
{

class NetworkPacket;

//utility functions
void BuildJSON(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddTimestamp(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddObject_Layers(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddObject_FrameMetadata(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddObject_DataLink(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddObject_Network(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddObject_Transport(NetworkPacket& np, Writer<StringBuffer>& writer);
void AddObject_Payload(NetworkPacket& np, Writer<StringBuffer>& writer);

}

#endif //CAPJSON_UTILITY_H
