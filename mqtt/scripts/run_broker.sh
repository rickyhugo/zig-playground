docker run \
  -p 1883:1883 \
  -v "$PWD"/mosquitto/config:/mosquitto/config:ro \
  -v "$PWD"/mosquitto/data:/mosquitto/data \
  -v "$PWD"/mosquitto/log:/mosquitto/log \
  eclipse-mosquitto:2
