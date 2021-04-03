#ifndef CAPJSON_JSON_H
#define CAPJSON_JSON_H

#include <ostream>


namespace CapJSON
{

class NetworkPacket;

class JSON
{
  public:
    JSON(NetworkPacket& np);
    friend std::ostream& operator<<(std::ostream& out, const JSON& j);

  private:
    std::string json_;
};

}
#endif // CAPJSON_JSON_H
