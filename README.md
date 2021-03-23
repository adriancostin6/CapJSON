# CapJSON

Command line tool for capturing network packets and storing them in JSON format.

## Getting started

To get a local copy of this repository run:

`git clone https://github.com/adriancostin6/CapJSON.git`

### Dependencies 

This project has the following dependencies:

- libtins 
- rapidjson

#### libtins

In order for the packet capture functionality to work, this project requires 
`libtins`. Instructions for setting up this library is provided below.

##### Linux / \*NIX operating systems:

The easiest way to get the library would be through your package manager if it
is available, if not follow the steps below to build it from source.

1. Go to the repository source directory: `cd CapJSON`
2. Make a directory for the external dependencies: `mkdir external`
3. Clone the libtins repository and build the source code and install the library

```
cd external
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build && cd build 
cmake ../ -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1
make && make install
```

##### Windows

Building libtins on Windows is done similarly, using Visual Studio. The only
additional requierment is for you to download the
[WinPCAP developer pack](https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip)
and place it inside the external directory.

```
cd CapJSON/external
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build && cd build 
cmake ../ -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1 -DPCAP_ROOT_DIR=../../WpdPack
```

After running these commands inside the shell you will have a Visual Studio 
solution from where you can build the `tins` project to generate the static library. 

#### rapidjson

`rapidjson` is a header only library, so you only need the include folder.

```
cd CapJSON/external
git clone https://github.com/Tencent/rapidjson.git
```

After doing this, the CMake build configuration  of the project wil automatically detect
where the include directory for `rapidjson` is located.

### Building

After sorting out the dependencies and placing them in the external directory
we can finally start building the project.

#### Linux / \*NIX operating systems

```
cd CapJSON && mkdir build && cd build
cmake ../
make
```

After running the commands listed above you should have an executable to run
the application. Do note that you need to give elevated privileges if you want
to use the packet capture functionality.


#### Windows

```
cd CapJSON && mkdir build && cd build
cmake ../
```

After running the commands listed above you can build the application by using
the Visual Studio solution or by running the following command: `cmake --build . --config Release`

The recommended build configuration is Release x64.

Once the executable has been generated, don't forget to run it with elevated 
privileges if you want to use the packet capture functionality.

