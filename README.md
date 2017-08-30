# File Signature Hijack

This project is a automation of a proof-of-concept demonstration from @mattifestation from Exploit-Monday

## Getting Started

Make a pull request, download the file as a zip file, or copy the code from Main.c 

### Prerequisites

This project was build using Visual Studio. You will need to include Shlwapi.lib to utilize the IsPathValid() function call. This project was built on Windows 10 x64. This has not been tested on other systems.

## Running the tests

This small code segment accepts two parameters. The first parameter is the full path of the digital signature you want to steal.

The second parameter is the full path to the executable file to receive the stolen signature.

Please note that, because of simplicity of the project, I did not include any functionality to handle spaces in the parameter paths. If your full path, for either parameter, has a space such as "C:\Programs (x86)\...\...\...\*.exe", the space will cause the application to crash.

## Built With

* [Visual Studio 2017](https://www.visualstudio.com/vs/whatsnew/)
* [Microsoft Windows API](https://msdn.microsoft.com/en-us/library/aa383723(VS.85).aspx)

## Authors

* **Mathew A. Stefanowich** - *Initial work*
* **Matt (Mattifestation) Graeber** - *Proof of concept/Paper*

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

