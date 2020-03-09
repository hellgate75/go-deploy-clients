<p align="center">
<image width="150" height="50" src="images/kube-go.png"></image>&nbsp;
<image width="260" height="410" src="images/golang-logo.png">
&nbsp;<image width="150" height="150" src="images/deploy-logo.png"></image>
</p><br/>
<br/>

# Go Deploy Client Modules

Go Deploy application default client module plugins


## How does it work a module

Module is composed by:

* Discovery interface, see [GetConnectionHandlerFactory](/proxy/proxy.go) interface function

* Connection Handler, implementing type [ConnectionHandler](https://github.com/hellgate75/go-deploy/blob/master/net/generic/interfaces.go) interface, it wraps the real client interface


## How to develop an external Linux Plugin Module


External Linux plugins must implement proxy as describe above.

Some implementation are available,

See please:

* [proxy](/proxy/proxy.go)

* [ssh client plugin module](/proxy/ssh/client/sshclient.go)

* [go-tcp client plugin module](/proxy/gotcp/client/gotcpclient.go)


## Rules

Any of the plugins must incorporate code for Discover and client features or together.

In the GetConnectionHandlerFactory you define match between client name and developed components.

You can envelope together multiple clients in a single plugin, accessing the right client via configured client type name

## References

Here list of linked repositories:

[Go Deploy](https://github.com/hellgate75/go-deploy)

[Go Deploy Modules](https://github.com/hellgate75/go-deploy-modules)



Enjoy the experience.



## License

The library is licensed with [LGPL v. 3.0](/LICENSE) clauses, with prior authorization of author before any production or commercial use. Use of this library or any extension is prohibited due to high risk of damages due to improper use. No warranty is provided for improper or unauthorized use of this library or any implementation.

Any request can be prompted to the author [Fabrizio Torelli](https://www.linkedin.com/in/fabriziotorelli) at the following email address:

[hellgate75@gmail.com](mailto:hellgate75@gmail.com)



