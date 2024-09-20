# Xena TPLD Dissector Plugin for Wireshark 

Xena offers a Wireshark integration via a dedicated LUA plugin. It allows users to easily read the information in the Xena test signature field.

> **IMPORTANT**
> The Xena TPLD dissector plugin doesn't support micro TPLD (6 bytes long).

![XTPLD Lua](images/xtpld.png)

## Install the XMP Parser
1. Go to `Wireshark Main Window > Help > About Wireshark > Folders > Personal Lua Plugins`, click the blue Location to open plugin folder.
2. Put ``xena_tpld.lua`` into the folder.
3. Restart Wireshark

![Personal Lua Plugins](images/install.png)