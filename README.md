# CUCKOO

The cuckoo malware sandbox plugin for AUCR
Huge thanks to the guys that develop cuckoo for making the best opensource malware sandbox please check the main page here
https://github.com/cuckoosandbox/cuckoo


## Organization Support slack

Please contact us in the organization chat and room to ask any questions!


## How to install

From the AUCR/aucr_app/plugins dir just git clone https://github.com/AUCR/cuckoo and run the flask app.

    git clone https://github.com/AUCR/AUCR
    cd AUCR/aucr_app/plugins
    git clone https://github.com/AUCR/cuckoo
    cd ../..
    EXPORT FLASK_APP=aucr.py
    flask run --host=127.0.0.1
    
    
### Install cuckoo in whatever way you prefer 
Setting up cuckoo isn't supported in this guide
The only thing that is required is the os environment variable CUCKOO_API_URL to best set to the cuckoo web front end.