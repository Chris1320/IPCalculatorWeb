import os
import sys
import ipaddress
import subprocess
from typing import Final
from typing import Iterable

from flask import Flask
from flask import request
from flask import url_for
from flask import redirect
from flask import render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


SECRET_KEY: Final[str] = os.getenv("SECRET_KEY", os.urandom(16).hex())
CWD: str = os.getenv("APP_CWD", os.getcwd())
DEBUG: bool = os.getenv("DEBUG_MODE", '').lower() == "true"


print(f"{SECRET_KEY=}")
print(f"{CWD=}")


class IPAddress:
    """
    An object representation of an IP address.
    """

    def __init__(self, ip: str):
        if len(ip) == 35:  # 32 bits, including the dots.
            ip = IPAddress._toDecimal(ip)

        if not IPAddress.isValidIP(ip):
            raise ValueError("Invalid IP address.")

        self._ip: str = ip  # decimal form

    @property
    def decimal(self) -> str:
        return self._ip

    @property
    def binary(self) -> str:
        return IPAddress._toBinary(self.decimal)

    @staticmethod
    def isValidIP(ip_to_check: str) -> bool:
        """
        Check if an IP address is in its valid decimal form.
        """

        ip: list[str] = ip_to_check.split('.')

        if len(ip) != 4:
            return False

        for octet in ip:
            if not octet.isdigit():
                return False

            if not 0 <= int(octet) <= 255:
                return False

        return True

    @staticmethod
    def _toBinary(decimal_ip: str) -> str:
        """
        Convert an IP address to its binary representation.
        """

        return '.'.join(
            [
                bin(int(x) + 256)[3:]
                for x in decimal_ip.split('.')
            ]
        )

    @staticmethod
    def _toDecimal(binary_ip: str) -> str:
        """
        Convert a binary representation of an IP address to its decimal representation.
        """

        return '.'.join(
            [
                str(int(x, 2))
                for x in binary_ip.split('.')
            ]
        )


class SubnetMask(IPAddress):
    def __init__(self, mask_or_cidr: str):
        if mask_or_cidr.startswith('/'):
            # if parameter is a CIDR.
            mask = SubnetMask._CIDRToMask(int(mask_or_cidr[1:]))

        elif len(mask_or_cidr) == 35:
            # if parameter is an IP in binary form.
            mask = SubnetMask._toDecimal(mask_or_cidr)

        else:
            mask = mask_or_cidr

        if not SubnetMask.isValidIP(mask):
            raise ValueError("Invalid subnet mask.")

        self._ip: str = mask # decimal form

    @property
    def cidr(self) -> int:
        return SubnetMask._maskToCIDR(self.decimal)

    @property
    def total(self) -> int:
        """
        Get the total number of addresses in a subnet.
        """

        return 2 ** (32 - self.cidr)

    @property
    def usable(self) -> int:
        """
        Get the number of usable addresses in a subnet.
        """

        return self.total - 2

    @property
    def interval(self) -> int:
        """
        Get the interval of the subnet mask.
        """

        octets = self.decimal.split('.')[::-1]

        for octet in octets:
            if int(octet) != 0:
                return 256 - int(octet)

        return 0

    @staticmethod
    def _maskToCIDR(mask: str) -> int:
        return SubnetMask._toBinary(mask).count('1')

    @staticmethod
    def _CIDRToMask(cidr: int) -> str:
        """
        Convert a CIDR (like `/24`) to its decimal representation (255.255.255.0).
        """

        mask: str = ''
        for i in range(4):
            if i < cidr // 8:
                mask += '255.'

            elif i == cidr // 8:
                mask += str(256 - 2**(8 - cidr % 8)) + '.'

            else:
                mask += '0.'

        return mask[:-1]


class Network:
    def __init__(self, network_address: IPAddress, subnet_mask: SubnetMask):
        self._network_address = network_address
        self._subnet_mask = subnet_mask

    @property
    def network_address(self) -> IPAddress:
        return self._network_address

    @property
    def subnet_mask(self) -> SubnetMask:
        return self._subnet_mask

    @property
    def broadcast_address(self) -> IPAddress:
        return self.next(self.subnet_mask.total - 1)

    @property
    def first_and_last_usable(self) -> tuple[IPAddress, IPAddress]:
        return (self.next(1), self.next(self.subnet_mask.total - 2))

    @property
    def usable(self) -> int:
        return self.subnet_mask.usable

    @property
    def total(self) -> int:
        return self.subnet_mask.total

    def next(self, n: int) -> IPAddress:
        """
        Get the nth next IP address in the network.
        """

        network_octets: list[str] = self.network_address.decimal.split('.')

        while n > 0:
            if int(network_octets[3]) + n <= 255:
                network_octets[3] = str(int(network_octets[3]) + n)
                break

            n -= 256 - int(network_octets[3])
            network_octets[3] = '0'
            if int(network_octets[2]) + 1 <= 255:
                network_octets[2] = str(int(network_octets[2]) + 1)
                continue

            network_octets[2] = '0'
            if int(network_octets[1]) + 1 <= 255:
                network_octets[1] = str(int(network_octets[1]) + 1)
                continue

            network_octets[1] = '0'
            if int(network_octets[0]) + 1 <= 255:
                network_octets[0] = str(int(network_octets[0]) + 1)
                continue

            raise ValueError("Too many hosts.")

        return IPAddress('.'.join(network_octets))


def getMaskFromNeededHosts(hosts: int, use_total: bool = False) -> SubnetMask | None:
    """
    Get the smallest subnet mask that can fit the number of hosts.
    If use_total is True, do not subtract broadcast and network address.
    """

    # loop from the smallest possible CIDR to the biggest and check if the hosts can fit there.
    if use_total:
        for i in range(32):
            if (2 ** i) >= hosts:
                return SubnetMask(f"/{32 - i}")

    else:
        for i in range(32):
            if (2 ** i) - 2 >= hosts:
                return SubnetMask(f"/{32 - i}")

    return None


class IPv6:
    def __init__(self, ip: str):
        # Check if the ip is a valid IPv6 address.
        if not IPv6.isValidIP(ip):
            raise ValueError("Invalid IPv6 address.")

        self._ip: str = IPv6._expandIP(ip)

    @property
    def hexadecimal(self) -> str:
        return self._ip

    @property
    def short_hex(self) -> str:
        return IPv6._shortenIP(self._ip)

    @staticmethod
    def _toHexadecimal(value: int) -> str:
        """
        Convert to Hexadecimal number system.
        """

        quotient = value
        result = ''
        letters = {
            10: 'a',
            11: 'b',
            12: 'c',
            13: 'd',
            14: 'e',
            15: 'f'
        }

        while quotient > 0:
            remainder = quotient % 16  # Get the remainder.
            # If remainder is > 10, replace it with equivalent hex letter.
            result += str(remainder) if remainder < 10 else letters[remainder]
            quotient = quotient // 16

        return result[::-1]

    @staticmethod
    def _toDecimal(value: str) -> int:
        """
        Convert to decimal number system.
        """

        letters = {
            'a': 10,
            'b': 11,
            'c': 12,
            'd': 13,
            'e': 14,
            'f': 15
        }

        exponent = 0  # The exponent of the right-most binary digit.
        result = 0

        for digit in value[::-1]:
            digit = letters[digit.lower()] if not digit.isdigit() else digit
            result += int(digit) * (16 ** exponent)

            exponent += 1  # Get the place value of the next octal digit.

        return result

    @staticmethod
    def isValidIP(ip_to_check: str) -> bool:
        """
        Check if it is a valid IPv6 address.
        """

        try:
            ipaddress.IPv6Address(ip_to_check)
            return True

        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _shortenIP(ip: str) -> str:
        ipv6 = ipaddress.IPv6Address(ip)
        return ipv6.compressed.lower()

    @staticmethod
    def _expandIP(ip: str) -> str:
        return ipaddress.IPv6Address(ip).exploded.lower()

    @staticmethod
    def _toBinary(hexadecimal_ip: str) -> str:
        """
        Convert an IPv6 address to its binary representation.
        """

        binary = ''

        for hextet in hexadecimal_ip.split(':'):
            binary += bin(IPv6._toDecimal(hextet))[2:].zfill(16)

        return binary


class IPv6SubnetMask(IPv6):
    def __init__(self, mask_or_cidr: str):
        if mask_or_cidr.startswith('/'):
            mask = IPv6SubnetMask._CIDRToMask(int(mask_or_cidr[1:]))

        else:
            mask = IPv6SubnetMask._expandIP(mask_or_cidr)

        if not IPv6SubnetMask.isValidIP(mask):
            raise ValueError("Invalid IPv6 subnet mask.")

        self._ip = mask

    @property
    def cidr(self) -> int:
        return IPv6SubnetMask._maskToCIDR(self._ip)

    @property
    def total(self) -> int:
        return 2 ** (128 - self.cidr)

    @property
    def interval(self) -> int:
        hextets = self._ip.split(':')[::-1]

        for hextet in hextets:
            if IPv6._toDecimal(hextet) != 0:
                return 65535 - IPv6._toDecimal(hextet)

        return 0

    @staticmethod
    def _maskToCIDR(mask: str) -> int:
        """
        Convert the mask to CIDR notation.
        """

        return IPv6SubnetMask._toBinary(mask).count('1')

    @staticmethod
    def _CIDRToMask(cidr: int) -> str:
        """
        Convert the CIDR notation to mask.
        """

        mask = ''

        for i in range(8):
            if cidr >= 16:
                mask += 'ffff'

            else:
                mask += IPv6._toHexadecimal(2 ** cidr - 1).ljust(4, '0')

            cidr -= 16

            if i != 7:
                mask += ':'

        return mask


def getIPv6MaskFromNeededHosts(hosts: int) -> IPv6SubnetMask | None:
    """
    Get the smallest subnet mask that an fit the number of hosts.
    """

    for i in range(128):
        if 2 ** i >= hosts:
            return IPv6SubnetMask(f"/{128 - i}")

    return None


def renderNetworkInfo(networks: Iterable[Network], share_url: str) -> str:
    return render_template(
        "network-info-result.html",
        title = "Get network information",
        getBroadcastAddr = lambda x: x.broadcast_address.decimal,
        getFirstUsable = lambda x: x.first_and_last_usable[0].decimal,
        getLastUsable = lambda x: x.first_and_last_usable[1].decimal,
        networks = networks,
        share_url = share_url
    )


def getCommitHash() -> str:
    try:
        commit_hash: str = subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd = CWD
        ).decode('utf-8').strip()
        return f"Site Version: {commit_hash}"

    except Exception:
        return ''


app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app = app,
    default_limits = ["1 per second"],
    storage_uri = "memory://",
    strategy = "fixed-window"
)


@app.route('/')
def indexPage() -> str:
    return render_template(
        "index.html",
        commit_hash = getCommitHash()
    )


@app.route("/admin/hooks/git-pull", methods=["POST"])
@limiter.limit("1 per minute")
def hooksGitPull():
    print("[i] Received git pull request")
    try:
        subprocess.run(
            ["git", "pull"],
            cwd = CWD,
            check = False
        )
        print(f"[i] Updated to {getCommitHash()}")
        return "OK"

    except Exception as e:
        return f"ERROR: {e}"


@app.route("/ip-address-calculator", methods = ["GET", "POST"])
def ipAddressCalculator() -> str:
    if request.method == "POST":
        try:
            ip = IPAddress(request.form["ipAddress"])
            return render_template(
                "ip-address-calculator-result.html",
                ip = ip
            )

        except Exception as e:
            return render_template("error.html", desc = e)

    else:
        return render_template("ip-address-calculator.html")


@app.route("/subnet-mask-calculator", methods = ["GET", "POST"])
def subnetMaskCalculator() -> str:
    if request.method == "POST":
        try:
            mask = SubnetMask(request.form["mask"])
            return render_template(
                "subnet-mask-calculator-result.html",
                mask = mask
            )

        except Exception as e:
            return render_template("error.html", desc = e)

    else:
        return render_template("subnet-mask-calculator.html")


@app.route("/subnet-mask-from-usable-hosts", methods = ["GET", "POST"])
def subnetMaskFromUsableHosts() -> str:
    if request.method == "POST":
        try:
            hosts = int(request.form["hosts"])
            use_total = "use_total" in request.form
            mask = getMaskFromNeededHosts(hosts, use_total)
            if mask is None:
                return render_template("error.html", desc="No subnet mask can fit that many hosts.")

            if use_total:
                desc = (
                    f"This subnet mask can fit {mask.total} hosts, "
                    "including network and broadcast addresses."
                )

            else:
                desc = f"This subnet mask can fit {mask.usable} hosts."

            return render_template(
                "subnet-mask-from-usable-hosts-result.html",
                desc = desc,
                mask = mask
            )

        except Exception as e:
            return render_template("error.html", desc = e)

    else:
        return render_template("subnet-mask-from-usable-hosts.html")


@app.route("/network-info", methods = ["GET", "POST"])
def networkInfo() -> str:
    if request.method == "POST":
        try:
            ip = IPAddress(request.form["ipAddress"])
            mask = SubnetMask(request.form["subnetMask"])
            network = (Network(ip, mask),)

            return renderNetworkInfo(
                networks = network,
                share_url = url_for("shareNetworkInfo", ip=ip.decimal, mask=mask.decimal)
            )

        except Exception as e:
            return render_template("error.html", desc=e)

    else:
        return render_template("network-info.html")


@app.route("/network-info/share", methods = ["GET"])
def shareNetworkInfo():
    """
    Requires two GET parameters: ip and mask.
    """

    try:
        ip = request.args.get("ip")
        mask = request.args.get("mask")
        if ip is None or mask is None:
            return redirect(url_for("networkInfo"))

        ip = IPAddress(ip)
        mask = SubnetMask(mask)
        network = (Network(ip, mask),)

        return renderNetworkInfo(
            networks = network,
            share_url = url_for("shareNetworkInfo", ip=ip.decimal, mask=mask.decimal)
        )

    except Exception as e:
        return render_template("error.html", desc=e)


@app.route("/design-a-network-clsm", methods = ["GET", "POST"])
def designANetworkCLSM() -> str:
    if request.method == "POST":
        try:
            ip = IPAddress(request.form["ipAddress"])
            mask = SubnetMask(request.form["subnetMask"])
            num_of_networks = int(request.form["num_of_networks"])
            networks = []

            first_ip = ip.decimal  # Get the first IP for the share url
            for _ in range(num_of_networks):
                network = Network(ip, mask)
                networks.append(network)
                ip = network.next(mask.total)

            return renderNetworkInfo(
                networks = networks,
                share_url = url_for(
                    "shareDesignANetworkCLSM",
                    n = num_of_networks,
                    ip = first_ip,
                    mask = mask.decimal
                )
            )

        except Exception as e:
            return render_template("error.html", desc=e)

    else:
        return render_template("design-a-network-clsm.html")


@app.route("/design-a-network-clsm/share", methods = ["GET"])
def shareDesignANetworkCLSM():
    """
    Requires three GET parameters: n (num_of_networks),ip, and mask
    """

    try:
        num_of_networks = request.args.get('n')
        ip = request.args.get("ip")
        mask = request.args.get("mask")
        if num_of_networks is None or ip is None or mask is None:
            return redirect(url_for("designANetworkCLSM"))

        num_of_networks = int(num_of_networks)
        ip = IPAddress(ip)
        mask = SubnetMask(mask)

        first_ip = ip.decimal  # Get the first IP for the share url
        networks = []
        for _ in range(num_of_networks):
            network = Network(ip, mask)
            networks.append(network)
            ip = network.next(mask.total)

        return renderNetworkInfo(
            networks = networks,
            share_url = url_for(
                "shareDesignANetworkCLSM",
                n = num_of_networks,
                ip = first_ip,
                mask = mask.decimal
            )
        )

    except Exception as e:
        return render_template("error.html", desc=e)


@app.route("/design-a-network-vlsm", methods=["GET", "POST"])
def designANetworkVLSM() -> str:
    if request.method == "POST":
        try:
            # Check if user finished the first part of the form
            if request.form.get("networks", None) is None:
                # This is the first part of the form.
                return render_template(
                    "design-a-network-vlsm2.html",
                    n = int(request.form.get("num_of_networks", 1))
                )

            # This is the 2nd part of the form.
            first_network_address = IPAddress(request.form["ipAddress"])
            network_quantity = int(request.form["networks"])
            network_masks = []
            for i in range(network_quantity):
                mask = request.form[f"mask{i}"]
                if mask.endswith('h'):
                    mask = getMaskFromNeededHosts(int(mask[:-1]), False)
                    if mask is None:
                        raise ValueError(
                            "No subnet mask can fit that many hosts."
                        )

                else:
                    mask = SubnetMask(mask)

                network_masks.append(mask)

            # sort network_masks by number of hosts
            network_masks.sort(key=lambda x: x.usable, reverse=True)

            # Save the first network address in
            # decimal form for sharing the result.
            first_network_address_share = first_network_address.decimal
            networks: list[Network] = []
            for _, mask in enumerate(network_masks):
                networks.append(Network(first_network_address, mask))
                first_network_address = networks[-1].next(mask.total)

            return renderNetworkInfo(
                networks = networks,
                share_url = url_for(
                    "shareDesignANetworkVLSM",
                    first = first_network_address_share,
                    masks = ','.join([f"/{str(mask.cidr)}" for mask in network_masks]),
                    n = network_quantity
                )
            )

        except Exception as e:
            return render_template("error.html", desc=e)

    else:
        return render_template("design-a-network-vlsm.html")


@app.route("/design-a-network-vlsm/share", methods=["GET"])
def shareDesignANetworkVLSM():
    try:
        first_network_address = request.args.get("first")
        network_quantity = request.args.get('n')
        network_masks = request.args.get("masks")
        if first_network_address is None or network_quantity is None or network_masks is None:
            return redirect(url_for("designANetworkVLSM"))

        first_network_address = IPAddress(first_network_address)
        network_quantity = int(network_quantity)
        network_masks = [SubnetMask(mask) for mask in network_masks.split(',')]

        # sort network_masks by number of hosts
        network_masks.sort(key=lambda x: x.usable, reverse=True)

        # Save the first network address in
        # decimal form for sharing the result.
        first_network_address_share = first_network_address.decimal
        networks: list[Network] = []
        for _, mask in enumerate(network_masks):
            networks.append(Network(first_network_address, mask))
            first_network_address = networks[-1].next(mask.total)

        return renderNetworkInfo(
            networks = networks,
            share_url = url_for(
                "shareDesignANetworkVLSM",
                first = first_network_address_share,
                masks = ','.join([f"/{str(mask.cidr)}" for mask in network_masks]),
                n = network_quantity
            )
        )

    except Exception as e:
        return render_template("error.html", desc=e)


@app.route("/ipv6-calculator", methods=["GET", "POST"])
def ipv6Calculator():
    if request.method == "POST":
        try:
            ip = IPv6(request.form["ipAddress"])
            return render_template(
                "ipv6-calculator-result.html",
                ip = ip
            )

        except Exception as e:
            return render_template("error.html", desc = e)

    else:
        return render_template("ipv6-calculator.html")


@app.route("/ipv6-subnet-mask-calculator", methods=["GET", "POST"])
def ipv6SubnetMaskCalculator():
    if request.method == "POST":
        try:
            mask = IPv6SubnetMask(request.form["mask"])
            return render_template(
                "ipv6-subnet-mask-calculator-result.html",
                mask = mask
            )

        except Exception as e:
            return render_template("error.html", desc = e)

    else:
        return render_template("ipv6-subnet-mask-calculator.html")


@app.route("/ipv6-subnet-mask-from-total-hosts", methods = ["GET", "POST"])
def ipv6SubnetMaskFromTotalHosts() -> str:
    if request.method == "POST":
        try:
            hosts = int(request.form["hosts"])
            mask = getIPv6MaskFromNeededHosts(hosts)
            if mask is None:
                return render_template("error.html", desc="No subnet mask can fit that many hosts.")

            return render_template(
                "ipv6-subnet-mask-from-total-hosts-result.html",
                mask = mask
            )

        except Exception as e:
            return render_template("error.html", desc = e)

    else:
        return render_template("ipv6-subnet-mask-from-total-hosts.html")


def main():
    app.run(debug=DEBUG)


if __name__ == "__main__":
    sys.exit(main())
