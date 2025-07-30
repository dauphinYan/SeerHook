TARGET = SocketHook.dll

SRC = SocketHook/SocketHook.cpp \
      Third/minHook/src/buffer.c \
      Third/minHook/src/hook.c \
      Third/minHook/src/trampoline.c \
      Third/minHook/src/hde/hde64.c \

CXXFLAGS = -I. \
           -I./Third/minHook/include \
           -Wall -O2 \
           -static-libgcc -static-libstdc++ \
           -shared

LDFLAGS = -lws2_32

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	del /f /q $(TARGET)
