#ifndef CAPJSON_JSON_H
#define CAPJSON_JSON_H

#include <iostream>

namespace CapJSON
{

class NetworkPacket;

class JSON
{
  public:
    JSON(NetworkPacket& np);
    JSON(const JSON& other) = default;

    //ensure std containers use move on size reallocation
    JSON(JSON&& other) noexcept = default;
    ~JSON() noexcept = default;

    //copy and move assignment operators
    JSON& operator=(const JSON& other) = default;
    JSON& operator=(JSON&& other) = default;
    
    friend std::ostream& operator<<(std::ostream& out, const JSON& j);

  private:
    std::string json_;
};

}
#endif // CAPJSON_JSON_H
