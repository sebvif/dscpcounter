# dscpcounter

Este programa cuenta la cantidad de paquetes por etiqueta de DSCP y sentido. La entrada es un archivo .pcap y una mac address de referencia, la cual se usara construir los filtros eth.src y eth.dst. Con estos el programá determina el sentido de los paquetes, lo cual es util para detectar el comportamiento del nodo y de la central en una red celular.

# instrucciones de instalacion

`
git clone http://github.com/sebvif/dscpcounter.git
cd dscpcounter
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
`

# instrucciones de uso

`
cd /path/to/dscpcounter
source venv/bin/activate
python3 dscpconter.py /path/to/dump.pcap 00:00:00:00:00:00
`

