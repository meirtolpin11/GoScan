# Modules Package

Welcome to the `Modules` package. Here you can create your own modules to manipulate the scan result.

* `core.go` - it's the `core` of the package. Here you should import your modules and load them.
* `data` folder - because of some **Golang** limitation I was unable to store the `modules` lists inside the core package. So `data` is just a package for 
storing information related to the modules. For example - The map of `<port>:<modules>` is stored in the `data` package
* `smb` - it's just an example module, you can take a look on it for inspiration. your own modules should be subpackages in this folder. So if you create a `http` module 
you should create `http` folder and write your module.

# Steps to create a module

1) Create a subfolder with the name of your module and then implement your module inside it
   * Your module should contain the following functions - 
     * `Load` - which will register your module to a particular port number
     * And a function which will implement your module's logic. You should keep the signature of - `func module(result *Types.Result) {}`
2) When you done - you need to add an import to the `core.go` file and `Module.Load()` to the `core.go` file's init function.
3) And thats it - when there will be a scan with the port you module is registered to, your module will be executed in the end of nmap probes scan.
