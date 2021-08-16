package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	fmt.Println(`WigleWifi-1.4,appRelease=1.0,model=cagertronix,release=11.0.0,device=some-pi,display=,board=zero,brand=any`)
	fmt.Println(`MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type`)
	w := csv.NewWriter(os.Stdout)

	devices, err := accessPoints(db)
	packets(db, devices, w)
	if err != nil {
		log.Fatal(err)
	}

}

func packets(db *sql.DB, accessPoints map[string]DeviceInfo, w *csv.Writer) error {
	rows, err := db.Query(`
		select ts_sec, sourcemac, phyname, lat, lon, signal, frequency, alt
		from packets
		where sourcemac != '00:00:00:00:00:00'
			  and lat != 0
			  and lon != 0
	`)

	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var (
			tsSec                    int64
			sourceMac, phyName       string
			lat, lon, alt, frequency float64
			signal                   int
		)

		err = rows.Scan(&tsSec, &sourceMac, &phyName, &lat, &lon, &signal, &frequency, &alt)
		if err != nil {
			return err
		}

		dev, ok := accessPoints[sourceMac]
		if !ok {
			continue
		}

		w.Write([]string{
			sourceMac,
			dev.SSId,
			dev.Crypto,
			dev.FirstSeen.UTC().Format("2006-01-02 15:04:05"),
			fmt.Sprint(frequencyToChannel(frequency)),
			fmt.Sprint(signal),    // TODO
			fmt.Sprint(lat),
			fmt.Sprint(lon),
			fmt.Sprint(alt),
			"0",
			"WIFI",
		})
	}
	w.Flush()

	return nil
}

type DeviceInfo struct {
	SSId      string
	FirstSeen time.Time
	Crypto    string
}

func accessPoints(db *sql.DB) (map[string]DeviceInfo, error) {
	rows, err := db.Query(`
		select devmac, first_time, avg_lat, avg_lon, device
		from devices
		where devmac != '00:00:00:00:00:00'
			  and type = 'Wi-Fi AP'
	`)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	m := make(map[string]DeviceInfo)

	for rows.Next() {
		var devMac string
		var firstSeen int64
		var avgLat, avgLon float64
		var device []byte
		err = rows.Scan(&devMac, &firstSeen, &avgLat, &avgLon, &device)
		if err != nil {
			return nil, err
		}

		var dev struct {
			Device struct {
				LastBeaconedSSID       string `json"dot11.device.last_beaconed_ssid"`
				LastBeaconedSSIDRecord struct {
					SSId     string `json:"dot11.advertisedssid.ssid"`
					CryptSet uint64 `json:"dot11.advertisedssid.crypt_set"`
				} `json:"dot11.device.last_beaconed_ssid_record"`
				AdvertisedSSIDMap []struct {
					SSId     string `json:"dot11.advertisedssid.ssid"`
					CryptSet uint64 `json:"dot11.advertisedssid.crypt_set"`
				} `json:"dot11.device.advertised_ssid_map"`
				RespondedSSIDMap []struct {
					SSId     string `json:"dot11.respondedssid.ssid"`
					CryptSet uint64 `json:"dot11.respondedssid.crypt_set"`
				} `json:"dot11.device.responded_ssid_map"`
			} `json:"dot11.device"`
		}
		err = json.Unmarshal(device, &dev)
		if err != nil {
			return nil, err
		}

		ssid := ""
		cryptSet := Crypt(0)
		if dev.Device.LastBeaconedSSID != "" {
			ssid = dev.Device.LastBeaconedSSID
		} else if dev.Device.LastBeaconedSSIDRecord.SSId != "" {
			ssid = dev.Device.LastBeaconedSSIDRecord.SSId
			cryptSet = Crypt(dev.Device.LastBeaconedSSIDRecord.CryptSet)
		} else if len(dev.Device.AdvertisedSSIDMap) > 0 {
			ssid = dev.Device.AdvertisedSSIDMap[0].SSId
			cryptSet = Crypt(dev.Device.AdvertisedSSIDMap[0].CryptSet)
		} else if len(dev.Device.RespondedSSIDMap) > 0 {
			ssid = dev.Device.RespondedSSIDMap[0].SSId
			cryptSet = Crypt(dev.Device.RespondedSSIDMap[0].CryptSet)
		}

		m[devMac] = DeviceInfo{
			SSId:      ssid,
			FirstSeen: time.Unix(firstSeen, 0),
			Crypto:    cryptSet.String(),
		}

	}

	return m, nil
}

type Crypt uint64

const (
	CryptNone    Crypt = 0
	CryptUnknown Crypt = 1 << (iota - 1)
	CryptWEP
	CryptLayer3
	CryptWEP40
	CryptWEP104
	CryptTKIP
	CryptWPA
	CryptPSK
	CryptAES_OCB
	CryptAES_CCM
	CryptWPAMigModde
	CryptEAP
	CryptLEAP
	CryptTTLS
	CryptTLS
	CryptPEAP
	CryptSAE
	CryptWPAOWE

	_
	_

	CryptISAKMP
	CryptPPTP
	CryptFortress
	CryptKeyGuard
	CryptUnknownProtected
	CryptUnknownNonWEP
	CryptWPS
	CryptVersionWPA
	CryptVersionWPA2
	CryptVersionWPA3
)

const (
	CryptProtectMask Crypt = 0xFFFF
)

func (c Crypt) String() string {
	s := new(strings.Builder)
	if c&CryptWPS != 0 {
		s.WriteString("[WPS] ")
	}
	if c&CryptProtectMask == CryptWEP {
		s.WriteString("[WEP] ")
	}

	if c&CryptWPA != 0 {
		var version, authVersion string

		if c&CryptTKIP != 0 {
			if c&CryptAES_CCM != 0 {
				version = "CCMP+TKIP"
			} else {
				version = "TKIP"
			}
		} else if c&CryptAES_CCM != 0 {
			version = "CCMP"
		}

		if c&CryptPSK != 0 {
			authVersion = "PSK"
		} else if c&CryptEAP != 0 {
			authVersion = "EAP"
		} else if c&CryptWPAOWE != 0 {
			authVersion = "OWE"
			//} else {
			//	authVersion = "UNKNOWN"
		}

		if c&CryptVersionWPA != 0 && c&CryptVersionWPA2 != 0 {
			fmt.Fprintf(s, "[WPA-%s-%s] [WPA2-%s-%s] ", authVersion, version, authVersion, version)
		} else if c&CryptVersionWPA2 != 0 {
			fmt.Fprintf(s, "[WPA2-%s-%s] ", authVersion, version)
			/*} else if c&CryptVersionWPA3 != 0 || c&CryptWPAOWE != 0 {
			fmt.Fprintf(s, "[WPA3-%s-%s] ", authVersion, version)*/
		} else {
			fmt.Fprintf(s, "[WPA-%s-%s] ", authVersion, version)
		}
	}

	return strings.TrimSpace(s.String()) + "[ESS]"
}

func frequencyToChannel(f float64) int {
	f = f / 1000

	switch {
	case f <= 0:
		return 0
	case f == 2484:
		return 14
	case f < 2484:
		return int((f - 2407) / 5)
	case f >= 4910 && f <= 4980:
		return int((f - 4000) / 5)
	case f <= 45000:
		return int((f - 5000) / 5)
	case f >= 58230 && f <= 6480:
		return int((f - 56160) / 2160)
	default:
		return int(f)
	}
}
