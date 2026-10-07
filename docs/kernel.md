# Kernel side

The kernel half of this stack lives in
[rubens-mt6895-mainline/linux](https://github.com/rubens-mt6895-mainline/linux) on the
`7.2-mt6895-xiaomi-rubens` branch. It is three things: a transport driver, a small uapi
header, and a device tree node.

## Files

| file | purpose |
| --- | --- |
| `drivers/misc/goodix_fp.c` | SPI transport bridge, reset line, regulator, IRQ |
| `include/uapi/linux/goodix_fp.h` | ioctl surface of `/dev/goodix_fp` |
| `arch/arm64/boot/dts/mediatek/mt6895-xiaomi-rubens.dts` | the `goodix-fp@0` node on `&spi3` |
| `arch/arm64/configs/rubens.config` | `CONFIG_GOODIX_FP=y` |

The driver arrives in commit `889d061a917e`; the device tree node and the defconfig
change come from `5a29101fe8bd`.

The driver deliberately does no protocol work. The sensor's command set, its firmware
blobs and the matching algorithm all live in the vendor TA, and the TA is run by the
userspace host in this repository. The kernel only moves bytes and controls the three
side resources.

## Device tree

```
&spi3 {
	pinctrl-names = "default";
	pinctrl-0 = <&fp_pins_default>;
	status = "okay";

	goodix-fp@0 {
		compatible = "goodix,gf-spi";
		reg = <0>;
		spi-max-frequency = <1000000>;
		vdd-supply = <&mt6368_vfp_reg>;
		reset-gpios = <&pio 216 GPIO_ACTIVE_HIGH>;
		interrupt-parent = <&pio>;
		interrupts = <136 IRQ_TYPE_EDGE_RISING>;
		pinctrl-names = "default";
		pinctrl-0 = <&fp_pins_reset>, <&fp_pins_eint>;
		status = "okay";
	};
};
```

The sensor sits on the SPI3_A pads (GPIO217 to 220, `fp_pins_default`). `vdd` is the
adjustable `mt6368_vfp` rail fed at 3.3 V. On the xaga boards the same footprint can
carry an FPC1540, which is fed from `mt6368_vibr` at 1.8 V instead; check your board
before reusing this node.

`reset-gpios` is declared active high on purpose. The sensor runs with the reset line
left high, and the driver emits an assert-low then release-high pulse on probe, which
lands the line where the sensor wants it.

## ioctl surface

`/dev/goodix_fp` is a character device. The header defines:

| ioctl | argument | meaning |
| --- | --- | --- |
| `GOODIX_FP_IOC_POWER` | `__u32` | `GOODIX_FP_POWER_OFF`, `_ON` or `_CYCLE` |
| `GOODIX_FP_IOC_RESET` | none | pulse the reset line |
| `GOODIX_FP_IOC_WAIT_FINGER` | `__u32` | wait for a finger-present edge, timeout in ms |
| `GOODIX_FP_IOC_FINGER_STATE` | `__u32` | current value of the presence line |
| `GOODIX_FP_IOC_RAW_XFER` | `struct goodix_fp_raw_xfer` | one transfer: transmit, then receive |

`struct goodix_fp_raw_xfer` carries `tx_len`, `rx_len`, a `tx` pointer and an `rx`
pointer, with `GOODIX_FP_RAW_MAX` (262144) as the per-call ceiling. This is the same
primitive the vendor platform layer offers the trustlet, so the host can hand the TA's
sensor accesses straight through.

Two caveats on our unit:

- `GOODIX_FP_IOC_WAIT_FINGER` never reports a press. GPIO136 floats and picks up 50 Hz
  mains noise, so the presence line is useless and captures have to be triggered by the
  user. The ioctl and the attribute are still there for boards where the line behaves.
- The rail is adjustable from 1.2 V to 3.5 V. We run it at 3.3 V.

## Building the module

Out of tree, against a tree configured for the device:

```
make -C <kernel-tree> M=$PWD modules
```

`CONFIG_GOODIX_FP` has to be reachable from that tree's configuration.
