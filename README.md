# pscan

pscan is a python program developed for basic port scanning on a network.

## Usage

```shell
python pscan [-h] [--ports PORTS [PORTS ...]] [--network] ip

positional arguments:
  ip                    the IP address of the machine to be scanned

optional arguments:
  -h, --help            show this help message and exit
  --ports PORTS [PORTS ...], -p PORTS [PORTS ...]
                        the ports to be tested by the scanner
  --network, -n         perform a network-wide search
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)