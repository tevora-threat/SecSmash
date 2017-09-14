### Overview ###
SecSmash is for leveraging credentials to these systems to enumerate connected hosts, and send commands to those hosts. 

For details on the idea behind the tool, and ways it can be used, check out the talk: <https://www.youtube.com/watch?v=M6pHI-bwuB4&index=3&list=PLjpIlpOLoRNRf4qID4oeAUvhkSGfWRAnd>


We are launching with Carbon Black and Tripwire integration. 

### Getting Started ###
pip install -r requirements.txt
python ./secsmash.py


### The Framework ###

We've built an HTTP integrator that takes inputs, and extractions to generate new inputs, to drive a chain of HTTP request to authenticate to the target system, enumerate connected hosts, and run commands. 

Integrations can also be built from scratch if they match the Integrator interface. 

We will be shoring up our documentation in the coming months and are hoping to see community involvement in module creation and sharing!
