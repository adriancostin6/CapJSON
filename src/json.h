#ifndef JSON_H
#define JSON_H

#include <ostream>

class NetworkPacket;

class JSON
{
  public:
    JSON(NetworkPacket& np);
    friend std::ostream& operator<<(std::ostream& out, const JSON& j);

  private:
    std::string json_;
};
#endif // JSON_H
