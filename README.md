# Intel&reg; QuickAssist Technology Plugin for RocksDB Storage Engine
The Intel&reg; QuickAssist Technology (QAT) plugin for RocksDB provides accelerated compression/decompression in RocksDB using QAT and [QATzip](https://github.com/intel/QATzip). It is dependent on the pluggable compression framework offered in [PR6717](https://github.com/facebook/rocksdb/pull/6717). Note: as the code is under review, it is subject to change. Please use the latest release of this plugin to ensure compatibility with the latest content of the pluggable compression PR.

For more information about Intel&reg; QuickAssist Technology, refer to the [QAT Programmer's Guide](https://cdrdv2.intel.com/v1/dl/getContent/743912) on the [Intel&reg; QAT Developer Zone](https://developer.intel.com/quickassist) page. Additionally, the online [QAT Hardware User Guide](https://intel.github.io/quickassist/index.html) is a valuable resource that provides guidance on setting up and optimizing QAT.
For more information about plugin support in RocksDB, refer to the [instructions](https://github.com/facebook/rocksdb/tree/main/plugin) in RocksDB and [PR 7918](https://github.com/facebook/rocksdb/pull/7918).

# Building RocksDB with the QAT Plugin
There are two ways to setup and configure QAT on a machine. One involves the Linux package manager, and the other involves compiling from source. This guide describes both methods and the steps required to build RocksDB with the plugin. 

### Install Dependencies (Method #1)
This is the first of two approaches that adds all necessary components to the system. It leverages the Linux distribution's built-in package manager. Please ensure the machine is using kernel version 6.0 or newer so that compatible library and firmware versions are applied. Do not combine the steps in this section with those described in method #2.

- Install QATzip and QATlib on RHEL 8, RHEL 9, CentOS Stream 8, or CentOS Stream 9.

```
sudo dnf install qatzip qatzip-devel qatzip-libs qatlib qatlib-devel qatlib-service qatlib-tests
```

- Install QATzip and QATlib on SLES 15 or openSUSE Leap 15.

```
sudo zypper install libqatzip3 qatzip qatzip-devel qatzip qatlib qatlib-devel
```

### Configure Devices (Method #1)
This is the first of two approaches that enables QAT compression/decompression on the system. Refer to the previous section for details on installing all dependencies. Do not combine the steps in this section with those described in method #2.

- Enable virtualization technology for directed I/O (VT-d) option in the BIOS menu.

- Ensure the machine is using kernel version 6.0 or newer, and enable the Intel IOMMU driver with scalable mode support with `intel_iommu=on,sm_on` included in the kernel boot parameters.

- Add currently logged in non-root user to the *qat* group and repeat as required for other non-root users.

```
sudo usermod -a -G qat `whoami`
```

- Increase the amount of locked memory available (e.g., 500 MB) for currently logged in non-root user and repeat as required for other non-root users. With QAT Gen 4, a minimum of 16 MB is needed for each VF plus whatever is required for the application.

```
echo `whoami` - memlock 500000  | sudo tee -a /etc/security/limits.conf > /dev/null
```

- Create the settings file used by all QAT devices.

```
sudo touch /etc/sysconfig/qat
```

- Enable the compression/decompression service and specify the engine distribution. This is accomplished by using the `POLICY` and `ServicesEnabled` fields. The values used will depend on the requirements of the applications using QAT. For example, the settings shown below only enable compression/decompression while allowing each application process to access at most 2 VFs. With QAT Gen 4, each device is connected to 16 VFs, so this example will have a limit of 32 application processes able to use QAT if there are 4 devices on the system. As an aside, `POLICY=0` means each QAT device's VFs are available to exactly one application process.

```
POLICY=2
ServicesEnabled=dc
```

- Reboot the machine to pick up the new settings. This is only required after installing, re-installing, or updating dependencies. In all other situations, this step can be skipped.

```
sudo reboot
```

- Restart the QAT service and check that all devices are setup properly.

```
sudo systemctl restart qat
sudo systemctl status qat
```

### Install Dependencies (Method #2)
This is the second of two approaches that adds all necessary components to the system. It compiles directly from source code and copies the files to the correct install locations. Do not combine the steps in this section with those described in method #1.

- Install QAT driver. All packages are available under [Intel QAT Drivers](https://www.intel.com/content/www/us/en/download/765501/intel-quickassist-technology-driver-for-linux-hw-version-2-0.html). In one of the packages, follow the steps in the README file to setup on a machine with QAT hardware. Note that only Intel&reg; 4XXX (QAT Gen 4) and newer chipset specific drivers are compatible with this plugin. Also, the kernel version must not be newer than 5.18 or compilation will fail.

- Install QATzip. Follow the instructions [here](https://github.com/intel/QATzip). The number of huge pages may also need to be modified to meet the top-level application's requirements. See the details in [performance-test-with-qatzip](https://github.com/intel/QATzip#performance-test-with-qatzip) for more information.

### Configure Devices (Method #2)
This is the second of two approaches that enables QAT compression/decompression on the system. Refer to the previous section for details on installing all dependencies. Do not combine the steps in this section with those described in method #1.

- Backup all configuration files to a separate folder in case the original settings need to be restored. For QAT Gen4, these files follow the */etc/4xxx_dev\*.conf* naming pattern.

- Ensure the plugin is able to access QAT via QATzip by modifying the configuration files in the */etc* folder to meet the needs of all applications. The example shown below provides a model for how configuration files can be changed. It disables all services except for compression/decompression, and it dedicates all hardware resources to applications that use QATzip. This is highlighted in the `[SHIM]` section where `NumberDcInstances` is the number of available logical compression/decompression instances per process, `NumProcesses` is the maximum number of processes that can access the QAT device represented by this configuration file, and `LimitDevAccess` indicates whether or not a process is restricted to the device. When ellipsis are used, that means the remaining portions are unchanged from the original configuration file or text is omitted to avoid repetition. So, if this scenario's modifications are applied to all configuration files on QAT Gen 4, at most 32 application processes can access the QAT devices at any particular time and each process can access at most 2 logical compression/decompression instances per QAT device without being restricted to a particular device.

```
...
[GENERAL]
ServicesEnabled = dc
...
[SSL]
NumberCyInstances = 0
NumberDcInstances = 0
NumProcesses = 0
...
[SHIM]
NumberCyInstances = 0
NumberDcInstances = 2
NumProcesses = 32
LimitDevAccess = 0

#Data Compression - User instance #0
Dc0Name = "Dc0"
Dc0IsPolled = 1
...
```

- Adjust the number of huge pages if necessary. Refer to the previous section on dependency installation for details.

- Restart the QAT service and check that all devices are setup properly.

```
sudo systemctl restart qat
sudo systemctl status qat
```

### Clone RocksDB and QAT Plugin
- Clone RocksDB with pluggable compression support. Replace the release tag as needed.

```
git clone --branch pluggable_compression https://github.com/lucagiac81/rocksdb.git
cd rocksdb
```

- Clone the QAT plugin in the plugin directory in RocksDB. Replace the release tag as needed.

```
git clone https://github.com/intel/qat-plugin-rocksdb.git plugin/qat_compressor
```

### Build with make
Please note that an application using this plugin may require additional compiler flags to cover specific requirements (e.g., security).

```
ROCKSDB_PLUGINS="qat_compressor" make -j release
```

If QATzip headers and libraries are not reachable from the standard environment paths, modify EXTRA_CXXFLAGS and EXTRA_LDFLAGS. Replace <qatzip_install_directory> with the paths of the QATzip installation directory on the system.

```
EXTRA_CXXFLAGS="-I<qatzip_install_directory>/include" EXTRA_LDFLAGS="-L<qatzip_install_directory>/src/.libs" ROCKSDB_PLUGINS="qat_compressor" make -j release
```

### Build with CMake
Please note that an application using this plugin may require additional compiler flags to cover specific requirements (e.g., security).

```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DROCKSDB_PLUGINS="qat_compressor"
make -j
```

If QATzip headers and libraries are not reachable from the standard environment paths, modify CXXFLAGS and LD_FLAGS in the cmake command

```
CXXFLAGS="-I/<qatzip_install_directory>/include" LDFLAGS="-L<qatzip_install_directory>/src/.libs" cmake .. -DCMAKE_BUILD_TYPE=Release -DROCKSDB_PLUGINS="qat_compressor"
```

### Verify Installation
To verify the installation, you can use db_bench and verify no errors are reported. The first command below enables the backup software path, and the second disables the backup software path.

```
./db_bench --benchmarks=fillseq --compression_type=com.intel.qat_compressor_rocksdb --compressor_options="sw_backup=enable"
./db_bench --benchmarks=fillseq --compression_type=com.intel.qat_compressor_rocksdb --compressor_options="sw_backup=disable"
```

Please note that log files will be generated in the executable's directory if any errors occur.

# Testing

- Install QAT, QATzip, RocksDB with pluggable compression support, and QAT plugin as described in the previous section.
- Install [googletest](https://github.com/google/googletest). One method is to use instructions listed [here](https://github.com/google/googletest/tree/main/googletest) that describe how to compile source. Another method is to use the built-in package manager in RHEL (`sudo dnf install gtest gtest-devel`) or SUSE (`sudo zypper install gtest`) based distributions. Please note that this plugin is only compatible with v1.10.0 or later releases of the test framework.
- Build RocksDB as a shared library

```
LIB_MODE=shared make -j release
```

- Go to the tests directory of the QAT plugin and build the tests with CMake

```
cd plugin/qat_compressor/tests
mkdir build
cd build
cmake ..
make run
```

If QATzip and RocksDB were not installed in default directories, the path can be specified as follows

```
cmake -DROCKSDB_PATH=<rocksdb_install_directory> -DQATzip_PATH=<qatzip_install_directory> ..
```

# Using the Plugin

To use the QAT plugin for compression/decompression, select it as compression type (com.intel.qat_compressor_rocksdb) just like any other algorithm. Refer to the examples in [PR6717](https://github.com/facebook/rocksdb/pull/6717). The reverse domain naming convention was selected to avoid conflicts in the future as more plugins are available. 

In the following examples, polling_mode is used as an example of compressor options. You can use any combination of supported options (refer to the Compressor Options section) in a semicolon-separated list.

To configure RocksDB using an option string

```
compressor={id=com.intel.qat_compressor_rocksdb;polling_mode=busy}
```

To configure RocksDB using an Options object

```
Options options;
ConfigOptions config_options;
  Status s = Compressor::CreateFromString(
      config_options,
      "id=com.intel.qat_compressor_rocksdb;polling_mode=busy",
      &options.compressor);
```

To select in db_bench

```
./db_bench --compression_type=com.intel.qat_compressor_rocksdb --compressor_options="polling_mode=busy"
```

# Compressor Options

The compressor offers several options:
- huffman_hdr
  - "dynamic": for compression, a Huffman table is computed each time (requires two passes over the data, but provides, in general, better compression ratio).
  - "static": a predefined Huffman table is used.
- data_fmt
  - "deflate_4b": data is in raw DEFLATE format with 4 byte header.
  - "deflate_gzip": data is in DEFLATE format wrapped by GZip header and footer.
  - "deflate_gzip_ext": data is in DEFLATE format wrapped by GZip extended header and footer.
  - "deflate_raw": data is in raw DEFLATE format.
  - Note: the value selected for this option only applies when the DEFLATE compression algorithm is used as the comp_algorithm option below.
- comp_lvl
  - [1, 9]: valid range when using DEFLATE compression algorithm.
  - [1, 12]: valid range when using LZ4 compression algorithm.
- comp_algorithm
  - "deflate": uses DEFLATE compression algorithm as defined in RFC 1951.
  - "lz4": uses LZ4 compression algorithm.
- sw_backup
  - "disable": will not use the software path if the hardware path fails.
  - "enable": will use the software path if the hardware path fails.
- hw_buff_sz
  - [1024, 2,147,483,648]: size of buffer (in bytes) passed into QAT hardware.
- strm_buff_sz
  - [1024, 2,147,478,528]: size of buffer (in bytes) passed into QAT hardware when using streaming APIs.
- input_sz_thrshold
  - [128, 1024]: input buffer threshold size (in bytes) where request lower than threshold uses the software path if available.
- wait_cnt_thrshold
  - [0, 2^(sizeof(unsigned int) * 8) - 1]: maximum number of retry attempts to make after unsuccessfully initializing QAT hardware.
- polling_mode
  - "periodical": calling thread will sleep until QAT processes input data - reduces CPU utilization but increases latency.
  - "busy": calling thread will stay active until QAT processes input data - reduces latency but increases CPU utilization.
- retry
  - "false": fail immediately if QAT hardware instance isn't found for compression or decompression operation.
  - "true": keep re-submitting request indefintely when QAT hardware instance isn't found for compression or decompression operation.
