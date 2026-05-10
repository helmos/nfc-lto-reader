// nfc-ltocm-go: Read LTO Cartridge Memory with libnfc, then parse and display it.
//
// Go rewrite / combination of nfc-ltocm + ltocm by Phil Pemberton <philpem@philpem.me.uk>
// Original: github.com/philpem/nfc-ltocm
//
// Licence: 2-clause BSD (same as original)
//
// References:
//   ECMA-319: https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-319.pdf
//
// Build requirements:
//   sudo apt install libnfc-dev   (Debian/Ubuntu)
//   go build -o nfc-ltocm-go .
//
// Usage:
//   ./nfc-ltocm-go                  read tag, parse and print to screen
//   ./nfc-ltocm-go -o <file.bin>    also save raw dump binary
//   ./nfc-ltocm-go -json            output parsed data as JSON
//   ./nfc-ltocm-go -v               include verbose hex dumps

package main

/*
#cgo pkg-config: libnfc
#include <nfc/nfc.h>
#include <stdlib.h>
#include <string.h>

// Thin wrappers so CGo can call vararg-free versions easily.
static nfc_device* ltocm_nfc_open(nfc_context *ctx) {
    return nfc_open(ctx, NULL);
}
*/
import "C"
import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

var (
	flagJSON    = flag.Bool("json", false, "output parsed data as JSON instead of text")
	flagVerbose = flag.Bool("v", false, "include raw hex dumps of each page")
	flagOutput  = flag.String("o", "", "save raw CM dump binary to `file` (default: don't save, just print)")
)

// ---------------------------------------------------------------------------
// NFC constants
// ---------------------------------------------------------------------------

const maxFrameLen = 264

const (
	ltocmACK  = 0x0A
	ltocmNACK = 0x05
)

var (
	ltocmRequestStandard   = []byte{0x45}
	ltocmRequestSerialNum  = []byte{0x93, 0x20}
	ltocmSelectTemplate    = []byte{0x93, 0x70, 0, 0, 0, 0, 0, 0, 0}
	ltocmReadBlockTemplate = []byte{0x30, 0, 0, 0}
	ltocmReadBlockExtTmpl  = []byte{0x21, 0, 0, 0, 0}
	ltocmReadBlockContinue = []byte{0x80}
)

const quietOutput = true

var pnd *C.nfc_device

// ---------------------------------------------------------------------------
// ISO 14443A CRC
// ---------------------------------------------------------------------------

func iso14443aCRC(data []byte) (lo, hi byte) {
	crc := uint16(0x6363)
	for _, b := range data {
		b ^= uint8(crc & 0xFF)
		b ^= b << 4
		crc = uint16(b)<<8 ^ uint16(b)<<3 ^ uint16(b)>>4 ^ crc>>8
	}
	return uint8(crc & 0xFF), uint8(crc >> 8)
}

func iso14443aCRCAppend(data []byte, length int) {
	lo, hi := iso14443aCRC(data[:length])
	data[length] = lo
	data[length+1] = hi
}

func iso14443aCRCValid(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	lo, hi := iso14443aCRC(data[:len(data)-2])
	return data[len(data)-2] == lo && data[len(data)-1] == hi
}

// ---------------------------------------------------------------------------
// NFC transceive helpers
// ---------------------------------------------------------------------------

func transmitBits(pbtTx []byte, szTxBits int) ([]byte, error) {
	var rxBuf [maxFrameLen]C.uint8_t
	txC := make([]C.uint8_t, len(pbtTx))
	for i, b := range pbtTx {
		txC[i] = C.uint8_t(b)
	}
	if !quietOutput {
		fmt.Printf("Sent bits (%d): % X\n", szTxBits, pbtTx)
	}
	ret := C.nfc_initiator_transceive_bits(
		pnd,
		(*C.uint8_t)(unsafe.Pointer(&txC[0])),
		C.size_t(szTxBits),
		nil,
		(*C.uint8_t)(unsafe.Pointer(&rxBuf[0])),
		C.size_t(maxFrameLen),
		nil,
	)
	if ret < 0 {
		return nil, fmt.Errorf("nfc_initiator_transceive_bits failed (code %d)", int(ret))
	}
	rxBits := int(ret)
	result := make([]byte, (rxBits+7)/8)
	for i := range result {
		result[i] = byte(rxBuf[i])
	}
	if !quietOutput {
		fmt.Printf("Received bits (%d): % X\n", rxBits, result)
	}
	return result, nil
}

func transmitBytes(pbtTx []byte) ([]byte, error) {
	var rxBuf [maxFrameLen]C.uint8_t
	txC := make([]C.uint8_t, len(pbtTx))
	for i, b := range pbtTx {
		txC[i] = C.uint8_t(b)
	}
	if !quietOutput {
		fmt.Printf("Sent bytes: % X\n", pbtTx)
	}
	ret := C.nfc_initiator_transceive_bytes(
		pnd,
		(*C.uint8_t)(unsafe.Pointer(&txC[0])),
		C.size_t(len(pbtTx)),
		(*C.uint8_t)(unsafe.Pointer(&rxBuf[0])),
		C.size_t(maxFrameLen),
		0,
	)
	if ret < 0 {
		return nil, fmt.Errorf("nfc_initiator_transceive_bytes failed (code %d)", int(ret))
	}
	result := make([]byte, int(ret))
	for i := range result {
		result[i] = byte(rxBuf[i])
	}
	if !quietOutput {
		fmt.Printf("Received bytes: % X\n", result)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// LTO-CM command functions
// ---------------------------------------------------------------------------

func ltocmReqStd() ([]byte, error) {
	rx, err := transmitBits(ltocmRequestStandard, 7)
	if err != nil {
		return nil, err
	}
	if len(rx) < 2 {
		return nil, fmt.Errorf("REQUEST STANDARD: too few bytes in response (%d)", len(rx))
	}
	return rx[:2], nil
}

func ltocmReqSerial() ([]byte, error) {
	rx, err := transmitBytes(ltocmRequestSerialNum)
	if err != nil {
		return nil, err
	}
	if len(rx) < 5 {
		return nil, fmt.Errorf("REQUEST SERIAL NUMBER: too few bytes (%d, want 5)", len(rx))
	}
	return rx[:5], nil
}

func ltocmSelect(serialNum []byte) (byte, int, error) {
	cmd := make([]byte, len(ltocmSelectTemplate))
	copy(cmd, ltocmSelectTemplate)
	copy(cmd[2:7], serialNum[:5])
	iso14443aCRCAppend(cmd, 7)
	rx, err := transmitBytes(cmd)
	if err != nil {
		return 0, 0, err
	}
	if len(rx) == 0 {
		return 0, 0, fmt.Errorf("SELECT: empty response")
	}
	return rx[0], len(rx), nil
}

func ltocmReadBlk(block int) ([]byte, error) {
	cmd := make([]byte, len(ltocmReadBlockTemplate))
	copy(cmd, ltocmReadBlockTemplate)
	cmd[1] = byte(block)
	iso14443aCRCAppend(cmd, 2)
	return transmitBytes(cmd)
}

func ltocmReadBlkExt(block int) ([]byte, error) {
	cmd := make([]byte, len(ltocmReadBlockExtTmpl))
	copy(cmd, ltocmReadBlockExtTmpl)
	cmd[1] = byte(block & 0xFF)
	cmd[2] = byte((block >> 8) & 0xFF)
	iso14443aCRCAppend(cmd, 3)
	return transmitBytes(cmd)
}

func ltocmReadBlkCnt() ([]byte, error) {
	return transmitBytes(ltocmReadBlockContinue)
}

func validateBlockResponse(rx []byte, blockLabel string) error {
	if len(rx) == 1 && rx[0] == ltocmNACK {
		return fmt.Errorf("%s: NACK", blockLabel)
	}
	if len(rx) != 18 {
		return fmt.Errorf("%s: insufficient response bytes (%d, want 18)", blockLabel, len(rx))
	}
	if !iso14443aCRCValid(rx) {
		return fmt.Errorf("%s: CRC error", blockLabel)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Safe big-endian helpers
// ---------------------------------------------------------------------------

func u8(b []byte, off int) uint8 {
	if off >= len(b) {
		return 0
	}
	return b[off]
}

func u16be(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint16(b[off:])
}

func u32be(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint32(b[off:])
}

func u64be(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return binary.BigEndian.Uint64(b[off:])
}

func u48be(b []byte, off int) uint64 {
	if off+6 > len(b) {
		return 0
	}
	var v uint64
	for i := 0; i < 6; i++ {
		v = (v << 8) | uint64(b[off+i])
	}
	return v
}

func readASCII(b []byte, off, length int) string {
	if off+length > len(b) {
		length = len(b) - off
	}
	if length <= 0 {
		return ""
	}
	var buf []byte
	for _, c := range b[off : off+length] {
		if c == 0x00 {
			break
		}
		if c >= 0x20 && c <= 0x7E {
			buf = append(buf, c)
		}
	}
	return strings.TrimSpace(string(buf))
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func hexStr(b []byte) string {
	return strings.ToUpper(hex.EncodeToString(b))
}

// ---------------------------------------------------------------------------
// Page descriptor
// ---------------------------------------------------------------------------

type PageDescriptor struct {
	Version   uint8
	PageID    uint16
	StartAddr uint16
}

func parsePageDescriptor(b []byte, off int) PageDescriptor {
	if off+4 > len(b) {
		return PageDescriptor{}
	}
	raw := b[off : off+4]
	return PageDescriptor{
		Version:   raw[0] >> 4,
		PageID:    (uint16(raw[0]&0x0F) << 8) | uint16(raw[1]),
		StartAddr: uint16(raw[2])<<8 | uint16(raw[3]),
	}
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

type CMManufacturerInfo struct {
	SerialNumber     string `json:"serial_number"`
	CheckByte        string `json:"check_byte"`
	TypeRaw          string `json:"type_raw"`
	MfgInfo          string `json:"mfg_info"`
	ChipCapacityKbit int    `json:"chip_capacity_kbit"`
}

type WriteInhibit struct {
	LastInhibitedBlock uint8 `json:"last_inhibited_block"`
	Block1ProtectFlag  uint8 `json:"block1_protect_flag"`
}

type CartridgeMfgInfo struct {
	PageVersion        uint8  `json:"page_version"`
	Manufacturer       string `json:"manufacturer"`
	SerialNumber       string `json:"serial_number"`
	CartridgeType      string `json:"cartridge_type"`
	Generation         int    `json:"generation"`
	IsWORM             bool   `json:"is_worm"`
	SupportsPartitions bool   `json:"supports_partitions"`
	DateOfMfg          string `json:"date_of_manufacture"`
	TapeLengthRaw      uint16  `json:"tape_length_raw"`      // raw CM field, units of 0.25 m
	TapeLengthM        float32 `json:"tape_length_m"`        // converted: raw × 0.25
	TapeThicknessNm    uint16  `json:"tape_thickness_nm"`    // nanometres (ECMA-319 Table 43)
	EmptyReelInertia   uint16 `json:"empty_reel_inertia"`
	HubRadius          uint16 `json:"hub_radius"`
	FullReelRadius     uint16 `json:"full_reel_radius"`
	MaxMediaSpeed      uint16 `json:"max_media_speed_mms"`
	LicenseCode        string `json:"license_code"`
	MfgUse             string `json:"manufacturer_use_hex"`
	CRC                string `json:"crc"`
}

type MediaMfgInfo struct {
	PageVersion     uint8  `json:"page_version"`
	ServowriteDate  string `json:"servowrite_date"`
	ServowriterMfg  string `json:"servowriter_manufacturer"`
	ServowriterType string `json:"servowriter_type"`
	ServowriterSerial string `json:"servowriter_serial"`
	TapeLot         string `json:"tape_lot"`
	CRC             string `json:"crc"`
}

type InitData struct {
	PageVersion uint8    `json:"page_version"`
	DriveMfg    string   `json:"drive_manufacturer"`
	DriveID     string   `json:"drive_id"`
	FormatType  string   `json:"format_type"`
	LPPositions []uint32 `json:"lp_positions"`
	CRC         string   `json:"crc"`
}

type TapeWritePass struct {
	PageVersion uint8     `json:"page_version"`
	WritePasses [8]uint32 `json:"write_passes"`
}

type WrapSection struct {
	Index     int    `json:"index"`
	RawHex    string `json:"raw_hex"`
	WritePass uint32 `json:"write_pass"`
}

type TapeDirectory struct {
	PageVersion  uint8         `json:"page_version"`
	FIDWritePass uint32        `json:"fid_write_pass"`
	ActiveWraps  []WrapSection `json:"active_wraps"`
	TotalWraps   int           `json:"total_wraps"`
}

type EODInfo struct {
	PageVersion         uint8  `json:"page_version"`
	WritePassAtEOD      uint32 `json:"write_pass_at_eod"`
	ThreadCount         uint32 `json:"thread_count"`
	RecordCountAtEOD    uint64 `json:"record_count_at_eod"`
	FileMarkCountAtEOD  uint64 `json:"file_mark_count_at_eod"`
	EODDataSetNumber    uint32 `json:"eod_dataset_number"`
	EODWrapSection      uint32 `json:"eod_wrap_section"`
	ValidityOfEOD       uint16 `json:"validity_of_eod"`
	FirstCQSetNumber    uint16 `json:"first_cq_set_number"`
	PhysicalPositionEOD uint32 `json:"physical_position_eod"`
	CRC                 string `json:"crc"`
}

type TapeAlertFlag struct {
	Bit         int    `json:"bit"`
	Description string `json:"description"`
}

type CartridgeStatus struct {
	PageVersion     uint8           `json:"page_version"`
	TapeAlertRaw    string          `json:"tape_alert_flags_hex"`
	TapeAlertFlags  []TapeAlertFlag `json:"tape_alert_flags_set,omitempty"`
	ThreadCount     uint32          `json:"thread_count"`
	CartridgeStatus uint16          `json:"cartridge_status"`
	CRC             string          `json:"crc"`
}

type MechanismRelated struct {
	PageVersion uint8  `json:"page_version"`
	DriveMfg    string `json:"drive_manufacturer"`
	DataHex     string `json:"data_hex,omitempty"`
}

type UsageInfo struct {
	PageVersion                  uint8  `json:"page_version"`
	PageID                       uint16 `json:"page_id"`
	SlotIndex                    int    `json:"slot_index"`
	DriveMfg                     string `json:"drive_manufacturer"`
	DriveID                      string `json:"drive_id"`
	SuspendedWritesAppend        uint16 `json:"suspended_writes_at_append"`
	ThreadCount                  uint32 `json:"thread_count"`
	TotalDatasetsWritten         uint64 `json:"total_datasets_written"`
	TotalDatasetsRead            uint64 `json:"total_datasets_read"`
	RecoveredWriteErrors         uint32 `json:"recovered_write_errors"`
	RecoveredReadErrors          uint32 `json:"recovered_read_errors"`
	UnrecoveredWriteErrors       uint16 `json:"unrecovered_write_errors"`
	UnrecoveredReadErrors        uint16 `json:"unrecovered_read_errors"`
	WriteServoErrors             uint16 `json:"write_servo_errors"`
	UnrecoveredWriteServoErrors  uint16 `json:"unrecovered_write_servo_errors"`
	BOMPasses                    uint32 `json:"beginning_of_medium_passes"`
	MOTPasses                    uint32 `json:"middle_of_tape_passes"`
	CRC                          string `json:"crc"`
}

type MAMAttribute struct {
	ID         uint16  `json:"id"`
	IDHex      string  `json:"id_hex"`
	Name       string  `json:"name"`
	Length     uint16  `json:"length"`
	ValueText  string  `json:"value_text,omitempty"`
	ValueHex   string  `json:"value_hex,omitempty"`
	ValueUint  *uint64 `json:"value_uint,omitempty"`
	SourcePage string  `json:"source_page"`
}

type SuspendedAppendEntry struct {
	Index  int    `json:"index"`
	RawHex string `json:"raw_hex"`
}

type SuspendedAppendWrites struct {
	PageVersion uint8                  `json:"page_version"`
	Entries     []SuspendedAppendEntry `json:"entries,omitempty"`
}

type HostSpecificPage struct {
	PageID      uint16 `json:"page_id"`
	PageVersion uint8  `json:"page_version"`
	DataHex     string `json:"data_hex,omitempty"`
}

type ExtendedPage struct {
	PageID      uint16 `json:"page_id"`
	PageVersion uint8  `json:"page_version"`
	Note        string `json:"note"`
	DataHex     string `json:"data_hex,omitempty"`
}

type AppSpecificPage struct {
	PageVersion  uint8          `json:"page_version"`
	FormatID     string         `json:"format_id,omitempty"`
	LTFSVolumeID string         `json:"ltfs_volume_id,omitempty"`
	EmbeddedMAM  []MAMAttribute `json:"embedded_mam_attributes,omitempty"`
}

type CMDump struct {
	FilePath      string             `json:"file_path"`
	FileSizeBytes int                `json:"file_size_bytes"`
	CMInfo        CMManufacturerInfo `json:"cm_manufacturer_info"`
	WriteInhibit  WriteInhibit       `json:"write_inhibit"`
	ProtectedPages struct {
		CartridgeMfg *CartridgeMfgInfo `json:"cartridge_manufacturer_info,omitempty"`
		MediaMfg     *MediaMfgInfo     `json:"media_manufacturer_info,omitempty"`
		InitData     *InitData         `json:"init_data,omitempty"`
	} `json:"protected_pages"`
	UnprotectedPages struct {
		TapeWritePass    *TapeWritePass         `json:"tape_write_pass,omitempty"`
		TapeDirectory    *TapeDirectory         `json:"tape_directory,omitempty"`
		EODInfo          *EODInfo               `json:"eod_info,omitempty"`
		CartridgeStatus  *CartridgeStatus       `json:"cartridge_status,omitempty"`
		MechanismRelated *MechanismRelated      `json:"mechanism_related,omitempty"`
		SuspendedAppend  *SuspendedAppendWrites `json:"suspended_append_writes,omitempty"`
		UsageInfo        []UsageInfo            `json:"usage_info,omitempty"`
		ExtendedPages    []ExtendedPage         `json:"extended_pages,omitempty"`
		AppSpecific      *AppSpecificPage       `json:"app_specific,omitempty"`
		HostSpecific     []HostSpecificPage     `json:"host_specific,omitempty"`
	} `json:"unprotected_pages"`
	MAMAttributes  []MAMAttribute `json:"mam_attributes,omitempty"`
	MAMStartOffset uint32         `json:"mam_start_offset"`
	MAMIsBlank     bool           `json:"mam_area_is_blank"`
	IsFormatted    bool           `json:"is_formatted"`
	Warnings       []string       `json:"warnings,omitempty"`
}

// ---------------------------------------------------------------------------
// TapeAlert flag definitions
// ---------------------------------------------------------------------------

var tapeAlertDefs = map[int]string{
	1: "Read Warning", 2: "Write Warning", 3: "Hard Error", 4: "Media",
	5: "Read Failure", 6: "Write Failure", 7: "Media Life", 8: "Not Data Grade",
	9: "Write Protect", 10: "No Removal", 11: "Cleaning Media", 12: "Unsupported Format",
	13: "Recoverable Mechanical Cartridge Failure", 14: "Unrecoverable Mechanical Cartridge Failure",
	15: "Memory Chip in Cartridge Failure", 16: "Forced Eject", 17: "Read Only Format",
	18: "Tape Directory Corrupted on Load", 19: "Nearing Media Life", 20: "Clean Now",
	21: "Clean Periodic", 22: "Expired Cleaning Media", 23: "Invalid Cleaning Tape",
	24: "Retention Requested", 25: "EOD Detected", 26: "EOD Not Found", 27: "EOD Early Warning",
	28: "Marks", 29: "Tape or Thread Media Error", 30: "Slow Area",
	31: "Unexpected Uncorrectable Error", 32: "Servo", 33: "Servo Software",
	34: "Loss of Servo", 35: "Tape Motion Failure", 36: "Tension Servo", 37: "Capstan Drive",
	38: "Torn Tape", 39: "Bulk Tape Failure", 40: "Interface", 41: "Eject Media",
	42: "Microcode Update Fail", 43: "Drive Humidity", 44: "Drive Temperature",
	45: "Drive Voltage", 46: "Predictive Failure", 47: "Diagnostics Required",
	48: "Loader Hardware A", 49: "Loader Stray Tape", 50: "Loader Hardware B",
	51: "Loader Door", 52: "Loader Hardware C", 53: "Loader Magazine",
	54: "Loader Predictive Failure", 64: "Lost Statistics",
	65: "Tape Directory Invalid at Unload", 66: "Tape System Area Write Failure",
	67: "Tape System Area Read Failure", 68: "No Start of Data",
}

func decodeTapeAlertFlags(raw uint64) []TapeAlertFlag {
	var flags []TapeAlertFlag
	for bit := 1; bit <= 64; bit++ {
		if raw&(1<<(64-bit)) != 0 {
			desc, ok := tapeAlertDefs[bit]
			if !ok {
				desc = fmt.Sprintf("Unknown flag %d", bit)
			}
			flags = append(flags, TapeAlertFlag{Bit: bit, Description: desc})
		}
	}
	return flags
}

// ---------------------------------------------------------------------------
// MAM attribute definitions
// ---------------------------------------------------------------------------

type mamDef struct {
	Name   string
	Format string // "ascii", "u64", "u32", "u16", "u8", "hex"
}

var mamDefs = map[uint16]mamDef{
	0x0000: {"Remaining Capacity", "u64"}, 0x0001: {"Maximum Capacity", "u64"},
	0x0002: {"TapeAlert Flags", "hex"}, 0x0003: {"Load Count", "u64"},
	0x0004: {"MAM Space Remaining", "u64"}, 0x0005: {"Assigning Organisation", "ascii"},
	0x0006: {"Formatted Density Code", "hex"}, 0x0007: {"Initialisation Count", "u16"},
	0x0008: {"Volume Identifier", "ascii"}, 0x0009: {"Volume Change Reference", "u32"},
	0x020A: {"Device Vendor/Serial at Last Load", "ascii"}, 0x020B: {"Device Vendor/Serial at Load-1", "ascii"},
	0x020C: {"Device Vendor/Serial at Load-2", "ascii"}, 0x020D: {"Device Vendor/Serial at Load-3", "ascii"},
	0x0220: {"Total MBytes Written in Medium Life", "u64"}, 0x0221: {"Total MBytes Read in Medium Life", "u64"},
	0x0222: {"Total MBytes Written in Current Load", "u64"}, 0x0223: {"Total MBytes Read in Current Load", "u64"},
	0x0224: {"Logical Position of First Encrypted Block", "u64"},
	0x0225: {"Logical Position of First Unencrypted Block after Encrypted Block", "u64"},
	0x0340: {"Medium Usage History", "hex"}, 0x0341: {"Partition Usage History", "hex"},
	0x0400: {"Medium Manufacturer", "ascii"}, 0x0401: {"Medium Serial Number", "ascii"},
	0x0402: {"Medium Length", "u32"}, 0x0403: {"Medium Width", "u32"},
	0x0404: {"Assigning Organisation (medium)", "ascii"}, 0x0405: {"Medium Density Code", "hex"},
	0x0406: {"Medium Manufacture Date", "ascii"}, 0x0407: {"MAM Capacity", "u64"},
	0x0408: {"Medium Type", "hex"}, 0x0409: {"Medium Type Information", "hex"},
	0x040A: {"Numeric Volume Identifier", "u64"}, 0x0800: {"Application Vendor", "ascii"},
	0x0801: {"Application Name", "ascii"}, 0x0802: {"Application Version", "ascii"},
	0x0803: {"User Medium Text Label", "ascii"}, 0x0804: {"Date/Time Last Written", "ascii"},
	0x0805: {"Text Localisation Identifier", "hex"}, 0x0806: {"Barcode", "ascii"},
	0x0807: {"Owning Host Textual Name", "ascii"}, 0x0808: {"Media Pool", "ascii"},
	0x0809: {"Partition User Text Label", "ascii"}, 0x080A: {"Load/Unload at Partition", "hex"},
	0x080B: {"Application Format Version", "ascii"}, 0x080C: {"Volume Coherency Information", "hex"},
}

func decodeMamAttribute(data []byte, off int, source string) (MAMAttribute, int) {
	if off+4 > len(data) {
		return MAMAttribute{}, -1
	}
	id := u16be(data, off)
	length := u16be(data, off+2)
	next := off + 4 + int(length)
	if next > len(data) {
		return MAMAttribute{}, -1
	}
	raw := data[off+4 : off+4+int(length)]

	def, known := mamDefs[id]
	name := def.Name
	if !known {
		name = fmt.Sprintf("Unknown (0x%04X)", id)
	}
	attr := MAMAttribute{ID: id, IDHex: fmt.Sprintf("0x%04X", id), Name: name, Length: length, SourcePage: source}

	if length == 0 {
		attr.ValueText = "(empty)"
		return attr, next
	}
	format := def.Format
	if !known {
		format = "hex"
	}
	switch format {
	case "ascii":
		attr.ValueText = strings.TrimSpace(strings.TrimRight(string(raw), "\x00"))
	case "u64":
		v := u64be(raw, 0); attr.ValueUint = &v; attr.ValueText = fmt.Sprintf("%d", v)
	case "u32":
		v := uint64(u32be(raw, 0)); attr.ValueUint = &v; attr.ValueText = fmt.Sprintf("%d", v)
	case "u16":
		v := uint64(u16be(raw, 0)); attr.ValueUint = &v; attr.ValueText = fmt.Sprintf("%d", v)
	case "u8":
		v := uint64(u8(raw, 0)); attr.ValueUint = &v; attr.ValueText = fmt.Sprintf("%d", v)
	default:
		attr.ValueHex = hexStr(raw)
	}
	return attr, next
}

func walkMAMAttributes(data []byte, startOffset int, source string) []MAMAttribute {
	return walkMAMAttributesBounded(data, startOffset, len(data), 0x0000, 0xFFFE, source)
}

func walkMAMAttributesBounded(data []byte, startOffset, endOffset int, minID, maxID uint16, source string) []MAMAttribute {
	if endOffset > len(data) {
		endOffset = len(data)
	}
	var attrs []MAMAttribute
	for i := startOffset; i+4 <= endOffset; {
		id := u16be(data, i)
		length := u16be(data, i+2)
		if id == 0xFFFF || (id == 0x0000 && length == 0) || id < minID || id > maxID || i+4+int(length) > endOffset {
			break
		}
		attr, next := decodeMamAttribute(data, i, source)
		if next < 0 {
			break
		}
		attrs = append(attrs, attr)
		i = next
	}
	return attrs
}

// ---------------------------------------------------------------------------
// Page parsers
// ---------------------------------------------------------------------------

func parseCMManufacturerInfo(data []byte) CMManufacturerInfo {
	chipKbit := 64
	if len(data) > 10000 {
		chipKbit = 128
	}
	return CMManufacturerInfo{
		SerialNumber: hexStr(data[0:5]), CheckByte: fmt.Sprintf("0x%02X", u8(data, 5)),
		TypeRaw: fmt.Sprintf("0x%04X", u16be(data, 6)), MfgInfo: readASCII(data, 8, 24),
		ChipCapacityKbit: chipKbit,
	}
}

func parseWriteInhibit(data []byte) WriteInhibit {
	return WriteInhibit{LastInhibitedBlock: u8(data, 0x20), Block1ProtectFlag: u8(data, 0x21)}
}

func cartridgeGenerationFromType(t uint16) (gen int, isWORM bool) {
	raw, worm := t, false
	if raw >= 0x0100 && raw <= 0x0103 {
		raw -= 0x0100; worm = true
	} else if raw >= 0x0110 && raw&0x00FF == 0x0010 {
		raw -= 0x0100; worm = true
	}
	switch raw {
	case 0x0000: return 1, worm
	case 0x0001: return 2, worm
	case 0x0002: return 3, worm
	case 0x0003: return 4, worm
	case 0x0010: return 5, worm
	case 0x0020: return 6, worm
	case 0x0030: return 7, worm
	case 0x0031: return 7, true
	case 0x0040: return 8, worm
	case 0x0050: return 9, worm
	}
	return 0, false
}

func parseCartridgeMfgInfo(data []byte, base int, ver uint8) *CartridgeMfgInfo {
	b := base
	typeRaw := u16be(data, b+22)
	gen, isWORM := cartridgeGenerationFromType(typeRaw)
	tapeLenRaw := u16be(data, b+32)
	// License Code is 4 ASCII bytes (e.g. "U107"), not a binary integer
	licenseCode := readASCII(data[b+44:b+48], 0, 4)
	return &CartridgeMfgInfo{
		PageVersion: ver, Manufacturer: readASCII(data, b+4, 8), SerialNumber: readASCII(data, b+12, 10),
		CartridgeType: fmt.Sprintf("0x%04X", typeRaw), Generation: gen, IsWORM: isWORM,
		SupportsPartitions: gen >= 6, DateOfMfg: readASCII(data, b+24, 8),
		TapeLengthRaw:   tapeLenRaw,
		TapeLengthM:     float32(tapeLenRaw) * 0.25, // CM field unit is 0.25 m per ECMA-319
		TapeThicknessNm: u16be(data, b+34),
		EmptyReelInertia: u16be(data, b+36), HubRadius: u16be(data, b+38),
		FullReelRadius: u16be(data, b+40), MaxMediaSpeed: u16be(data, b+42),
		LicenseCode: licenseCode, MfgUse: hexStr(data[b+48 : b+60]),
		CRC: fmt.Sprintf("0x%08X", u32be(data, b+60)),
	}
}

func parseMediaMfgInfo(data []byte, base int, ver uint8) *MediaMfgInfo {
	return &MediaMfgInfo{
		PageVersion:       ver,
		ServowriteDate:    readASCII(data, base+4,  8),
		ServowriterMfg:    readASCII(data, base+12, 8),
		ServowriterType:   readASCII(data, base+20, 8),
		ServowriterSerial: readASCII(data, base+28, 16),
		TapeLot:           readASCII(data, base+44, 7),
		CRC:               fmt.Sprintf("0x%08X", u32be(data, base+60)),
	}
}

func parseInitData(data []byte, base int, ver uint8) *InitData {
	lps := make([]uint32, 6)
	for i := range lps {
		lps[i] = u32be(data, base+24+i*4)
	}
	return &InitData{PageVersion: ver, DriveMfg: readASCII(data, base+4, 8), DriveID: readASCII(data, base+12, 10),
		FormatType: fmt.Sprintf("0x%04X", u16be(data, base+22)), LPPositions: lps,
		CRC: fmt.Sprintf("0x%08X", u32be(data, base+60))}
}

func parseTapeWritePass(data []byte, base int, ver uint8) *TapeWritePass {
	var wps [8]uint32
	for i := range wps {
		wps[i] = u32be(data, base+16+i*4)
	}
	return &TapeWritePass{PageVersion: ver, WritePasses: wps}
}

func parseTapeDirectory(data []byte, base int, ver uint8) *TapeDirectory {
	var active []WrapSection
	for i := 0; i < 96; i++ {
		off := base + 16 + i*16
		if off+16 > len(data) {
			break
		}
		raw := data[off : off+16]
		if !allZero(raw) {
			active = append(active, WrapSection{Index: i, RawHex: hexStr(raw), WritePass: u32be(raw, 0)})
		}
	}
	return &TapeDirectory{PageVersion: ver, FIDWritePass: u32be(data, base+4), ActiveWraps: active, TotalWraps: 96}
}

func parseEODInfo(data []byte, base int, ver uint8) *EODInfo {
	b := base
	return &EODInfo{
		PageVersion: ver, WritePassAtEOD: u32be(data, b+4), ThreadCount: u32be(data, b+8),
		RecordCountAtEOD: u48be(data, b+12), FileMarkCountAtEOD: u48be(data, b+18),
		EODDataSetNumber: u32be(data, b+24), EODWrapSection: u32be(data, b+28),
		ValidityOfEOD: u16be(data, b+32), FirstCQSetNumber: u16be(data, b+34),
		PhysicalPositionEOD: u32be(data, b+36), CRC: fmt.Sprintf("0x%08X", u32be(data, b+60)),
	}
}

func parseCartridgeStatus(data []byte, base int, ver uint8) *CartridgeStatus {
	raw := u64be(data, base+4)
	return &CartridgeStatus{
		PageVersion: ver, TapeAlertRaw: fmt.Sprintf("0x%016X", raw),
		TapeAlertFlags: decodeTapeAlertFlags(raw), ThreadCount: u32be(data, base+12),
		CartridgeStatus: u16be(data, base+16), CRC: fmt.Sprintf("0x%08X", u32be(data, base+28)),
	}
}

func parseMechanismRelated(data []byte, base int, ver uint8, verbose bool) *MechanismRelated {
	m := &MechanismRelated{PageVersion: ver, DriveMfg: readASCII(data, base+4, 8)}
	if verbose && base+384 <= len(data) {
		m.DataHex = hexStr(data[base : base+384])
	}
	return m
}

func parseUsageInfo(data []byte, base int, ver uint8, pageID uint16, slot int) UsageInfo {
	b := base
	// ECMA-319 Usage Information page layout:
	//   +04: Drive Manufacturer (8 bytes ASCII)
	//   +0C: Drive Serial Number (16 bytes ASCII, null-padded)
	//   +1C: Suspended Writes Appended (u16, 2 bytes)  [+2 bytes reserved]
	//   +20: Thread Count (u32)
	//   +24: (4 bytes reserved/padding)
	//   +28: Total Datasets Written (u64)
	//   +30: Total Datasets Read (u64)
	//   +38: Recovered Write Errors (u32)
	//   +3C: Recovered Read Errors (u32)
	//   +40: Unrecovered Write Errors (u16)
	//   +42: Unrecovered Read Errors (u16)
	//   +44: Write Servo Errors (u16)
	//   +46: Unrecovered Write Servo Errors (u16)
	//   +48: Beginning-of-Medium Passes (u32)
	//   +4C: Middle-of-Tape Passes (u32)
	//   +5C: CRC (u32)
	return UsageInfo{
		PageVersion:                 ver,
		PageID:                      pageID,
		SlotIndex:                   slot,
		DriveMfg:                    readASCII(data, b+4, 8),
		DriveID:                     readASCII(data, b+12, 16), // 16 bytes, not 10
		SuspendedWritesAppend:       u16be(data, b+28),
		ThreadCount:                 u32be(data, b+32),
		TotalDatasetsWritten:        u64be(data, b+36),
		TotalDatasetsRead:           u64be(data, b+44),
		RecoveredWriteErrors:        u32be(data, b+52),
		RecoveredReadErrors:         u32be(data, b+56),
		UnrecoveredWriteErrors:      u16be(data, b+60),
		UnrecoveredReadErrors:       u16be(data, b+62),
		WriteServoErrors:            u16be(data, b+64),
		UnrecoveredWriteServoErrors: u16be(data, b+66),
		BOMPasses:                   u32be(data, b+68),
		MOTPasses:                   u32be(data, b+72),
		CRC:                         fmt.Sprintf("0x%08X", u32be(data, b+92)),
	}
}

func parseSuspendedAppend(data []byte, base int, ver uint8) *SuspendedAppendWrites {
	var entries []SuspendedAppendEntry
	for i := 0; i < 14; i++ {
		off := base + 8 + i*8
		if off+8 > len(data) {
			break
		}
		raw := data[off : off+8]
		if !allZero(raw) {
			entries = append(entries, SuspendedAppendEntry{Index: i, RawHex: hexStr(raw)})
		}
	}
	return &SuspendedAppendWrites{PageVersion: ver, Entries: entries}
}

func parseHostSpecific(data []byte, base int, pageID uint16, ver uint8) HostSpecificPage {
	h := HostSpecificPage{PageID: pageID, PageVersion: ver}
	pageLen := int(u16be(data, base+2))
	if base+4+pageLen <= len(data) && !allZero(data[base+4:base+4+pageLen]) && *flagVerbose {
		h.DataHex = hexStr(data[base+4 : base+4+pageLen])
	}
	return h
}

func indexBytes(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
outer:
	for i := 0; i <= len(haystack)-len(needle); i++ {
		for j, b := range needle {
			if haystack[i+j] != b {
				continue outer
			}
		}
		return i
	}
	return -1
}

func scanForMAMBlock(data []byte, start, end int) []MAMAttribute {
	if end > len(data) {
		end = len(data)
	}
	for i := start; i+4 <= end; i++ {
		id := u16be(data, i)
		if id < 0x0800 || id > 0x08FF {
			continue
		}
		length := u16be(data, i+2)
		if length > 512 || i+4+int(length) > end {
			continue
		}
		if attrs := walkMAMAttributesBounded(data, i, end, 0x0800, 0x08FF, "page_0x200_embedded"); len(attrs) >= 3 {
			return attrs
		}
	}
	return nil
}

func parseAppSpecific(data []byte, base int, ver uint8) *AppSpecificPage {
	page := &AppSpecificPage{PageVersion: ver}
	b := base + 4
	if b+6 > len(data) {
		return page
	}
	if fid := readASCII(data, b, 7); strings.HasPrefix(fid, "MAM") {
		page.FormatID = fid
	}
	ltfsMarker := []byte{'+', 'L', 'T', 'F', 'S', 0x00}
	payload := data[base+4:]
	if idx := indexBytes(payload, ltfsMarker); idx >= 0 {
		uuidStart := idx + len(ltfsMarker)
		uuidEnd := uuidStart
		for uuidEnd < len(payload) && payload[uuidEnd] != 0x00 {
			uuidEnd++
		}
		if uuidEnd > uuidStart {
			page.LTFSVolumeID = string(payload[uuidStart:uuidEnd])
		}
	}
	page.EmbeddedMAM = scanForMAMBlock(data, base+4, base+4+int(u16be(data, base+2)))
	return page
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

func parseDumpBytes(data []byte, label string) (*CMDump, error) {
	if len(data) < 0x40 {
		return nil, fmt.Errorf("data too small (%d bytes); minimum valid CM dump is 64 bytes", len(data))
	}
	dump := &CMDump{FilePath: label, FileSizeBytes: len(data)}
	dump.CMInfo = parseCMManufacturerInfo(data)
	dump.WriteInhibit = parseWriteInhibit(data)

	// Walk protected page table
	var unprotTableAddr uint16

	i := 0x24
	for i+4 <= len(data) {
		desc := parsePageDescriptor(data, i)
		if desc.PageID == 0xFFF && desc.Version == 0 {
			unprotTableAddr = desc.StartAddr
			i += 4
			break
		}
		switch desc.PageID {
		case 0x001:
			if int(desc.StartAddr)+64 <= len(data) {
				dump.ProtectedPages.CartridgeMfg = parseCartridgeMfgInfo(data, int(desc.StartAddr), desc.Version)
			}
		case 0x002:
			if int(desc.StartAddr)+64 <= len(data) {
				dump.ProtectedPages.MediaMfg = parseMediaMfgInfo(data, int(desc.StartAddr), desc.Version)
			}
		case 0x101:
			if int(desc.StartAddr)+64 <= len(data) {
				dump.ProtectedPages.InitData = parseInitData(data, int(desc.StartAddr), desc.Version)
			}
}
		i += 4
	}

	if unprotTableAddr == 0 {
		dump.Warnings = append(dump.Warnings, "protected page table EOPT not found; unprotected pages and MAM unavailable")
		return dump, nil
	}

	// Walk unprotected page table
	var mamStartAddr uint16
standardPagesFound := 0
	i = int(unprotTableAddr)
	for i+4 <= len(data) {
		desc := parsePageDescriptor(data, i)
		if desc.PageID == 0xFFF && desc.Version == 0 {
			mamStartAddr = desc.StartAddr
			break
		}
		base := int(desc.StartAddr)
		switch {
		case desc.PageID == 0x102 && base+48 <= len(data):
			dump.UnprotectedPages.TapeWritePass = parseTapeWritePass(data, base, desc.Version); standardPagesFound++
		case desc.PageID == 0x103 && base+16 <= len(data):
			dump.UnprotectedPages.TapeDirectory = parseTapeDirectory(data, base, desc.Version); standardPagesFound++
		case desc.PageID == 0x104 && base+64 <= len(data):
			dump.UnprotectedPages.EODInfo = parseEODInfo(data, base, desc.Version); standardPagesFound++
		case desc.PageID == 0x105 && base+32 <= len(data):
			dump.UnprotectedPages.CartridgeStatus = parseCartridgeStatus(data, base, desc.Version); standardPagesFound++
		case desc.PageID == 0x106 && base+12 <= len(data):
			dump.UnprotectedPages.MechanismRelated = parseMechanismRelated(data, base, desc.Version, *flagVerbose); standardPagesFound++
		case desc.PageID == 0x107 && base+8 <= len(data):
			dump.UnprotectedPages.SuspendedAppend = parseSuspendedAppend(data, base, desc.Version); standardPagesFound++
		case desc.PageID >= 0x108 && desc.PageID <= 0x10B && base+64 <= len(data):
			u := parseUsageInfo(data, base, desc.Version, desc.PageID, int(desc.PageID-0x108))
			dump.UnprotectedPages.UsageInfo = append(dump.UnprotectedPages.UsageInfo, u); standardPagesFound++
		case desc.PageID >= 0x10C && desc.PageID <= 0x10E && base+4 <= len(data):
			pageLen := int(u16be(data, base+2))
			if pageLen == 0 || base+4+pageLen > len(data) {
				pageLen = 64
			}
			ep := ExtendedPage{PageID: desc.PageID, PageVersion: desc.Version, Note: "extended drive statistics"}
			if *flagVerbose && base+4+pageLen <= len(data) {
				ep.DataHex = hexStr(data[base : base+4+pageLen])
			}
			dump.UnprotectedPages.ExtendedPages = append(dump.UnprotectedPages.ExtendedPages, ep); standardPagesFound++
		case desc.PageID == 0x200 && base+8 <= len(data):
			if pageLen := int(u16be(data, base+2)); base+4+pageLen <= len(data) {
				dump.UnprotectedPages.AppSpecific = parseAppSpecific(data, base, desc.Version); standardPagesFound++
			}
		case desc.PageID >= 0x180 && desc.PageID <= 0x18F && base+4 <= len(data):
			dump.UnprotectedPages.HostSpecific = append(dump.UnprotectedPages.HostSpecific,
				parseHostSpecific(data, base, desc.PageID, desc.Version))
		}
		i += 4
	}

	dump.IsFormatted = dump.ProtectedPages.InitData != nil || standardPagesFound > 0

	if !dump.IsFormatted {
		dump.Warnings = append(dump.Warnings, "no operational pages found - cartridge appears unformatted/unused (never loaded into a drive)")
	}


	// MAM attribute area
	dump.MAMStartOffset = uint32(mamStartAddr)
	if mamStartAddr > 0 && int(mamStartAddr) < len(data) {
		if allZero(data[mamStartAddr:]) {
			dump.MAMIsBlank = true
		} else {
			dump.MAMAttributes = walkMAMAttributes(data, int(mamStartAddr), "mam_area")
			if len(dump.MAMAttributes) == 0 {
				dump.Warnings = append(dump.Warnings,
					fmt.Sprintf("MAM area at 0x%04X appears non-zero but no valid TLV attributes found", mamStartAddr))
			}
		}
	} else if mamStartAddr == 0 {
		dump.Warnings = append(dump.Warnings, "unprotected page table EOPT not found; MAM area location unknown")
	}

	return dump, nil
}

// ---------------------------------------------------------------------------
// Text output
// ---------------------------------------------------------------------------

func printDump(d *CMDump) {
	sep := strings.Repeat("─", 60)
	h := func(title string) { fmt.Printf("\n%s\n%s\n%s\n", sep, title, sep) }

	fmt.Printf("LTO Cartridge Memory - %s\n", d.FilePath)
	fmt.Printf("Data size: %d bytes (0x%04X)\n", d.FileSizeBytes, d.FileSizeBytes)
	for _, w := range d.Warnings {
		fmt.Printf("\n  ⚠  %s\n", w)
	}

	h("CM MANUFACTURER INFO  (0x0000)")
	ci := d.CMInfo
	fmt.Printf("  CM Serial Number : %s\n  Check Byte       : %s\n  Type             : %s\n  Mfg Info         : %s\n  Chip Capacity    : %dkbit\n",
		ci.SerialNumber, ci.CheckByte, ci.TypeRaw, ci.MfgInfo, ci.ChipCapacityKbit)
	wi := d.WriteInhibit
	fmt.Printf("\n  Write-Inhibit Last Block : %d\n  Block 1 Protect Flag     : %d\n", wi.LastInhibitedBlock, wi.Block1ProtectFlag)

	if p := d.ProtectedPages.CartridgeMfg; p != nil {
		h("CARTRIDGE MANUFACTURER INFO  (page 0x001)")
		fmt.Printf("  Manufacturer        : %s\n  Serial Number       : %s\n  Cartridge Type      : %s\n",
			p.Manufacturer, p.SerialNumber, cartridgeTypeName(p.CartridgeType))
		if p.Generation > 0 {
			wormStr, partStr := "", ""
			if p.IsWORM { wormStr = "  WORM" }
			if p.SupportsPartitions { partStr = "  multi-partition capable" }
			fmt.Printf("  Generation          : LTO-%d%s%s\n", p.Generation, wormStr, partStr)
		}
		if !d.IsFormatted { fmt.Printf("  Status              : unformatted / never loaded\n") }
		fmt.Printf("  Date of Mfg         : %s\n  Tape Length         : %.0f m  (%d raw × 0.25)\n  Tape Thickness      : %d nm  (%.3f µm)\n",
			p.DateOfMfg, p.TapeLengthM, p.TapeLengthRaw, p.TapeThicknessNm, float64(p.TapeThicknessNm)/1000.0)
		if p.MaxMediaSpeed > 0 { fmt.Printf("  Max Media Speed     : %d mm/s\n", p.MaxMediaSpeed) }
		fmt.Printf("  License Code        : %s\n  Mfg Use             : %s\n  CRC                 : %s\n",
			p.LicenseCode, p.MfgUse, p.CRC)
	}

	if p := d.ProtectedPages.MediaMfg; p != nil {
		h("MEDIA MANUFACTURER INFO  (page 0x002)")
		fmt.Printf("  Servowrite Date    : %s\n  Servowriter Mfg    : %s\n  Servowriter Type   : %s\n  Servowriter Serial : %s\n  Tape Lot           : %s\n  CRC                : %s\n",
			p.ServowriteDate, p.ServowriterMfg, p.ServowriterType, p.ServowriterSerial, p.TapeLot, p.CRC)
	}

	if p := d.ProtectedPages.InitData; p != nil {
		h("INITIALISATION DATA  (page 0x101)")
		fmt.Printf("  Formatting Drive Mfg : %s\n  Drive ID             : %s\n  Format Type          : %s\n",
			p.DriveMfg, p.DriveID, p.FormatType)
		for n, pos := range p.LPPositions {
			if pos != 0 { fmt.Printf("  LP%d Position         : 0x%08X  (%d)\n", n+1, pos, pos) }
		}
		fmt.Printf("  CRC                  : %s\n", p.CRC)
	}

	if p := d.UnprotectedPages.TapeWritePass; p != nil {
		h("TAPE WRITE PASS  (page 0x102)")
		for i, wp := range p.WritePasses { fmt.Printf("  Pass %d : %d\n", i, wp) }
	}

	if p := d.UnprotectedPages.EODInfo; p != nil {
		h("EOD INFORMATION  (page 0x104)")
		fmt.Printf("  Write Pass at EOD       : %d\n  Thread Count            : %d\n  Record Count at EOD     : %d\n"+
			"  File Mark Count at EOD  : %d\n  EOD Dataset Number      : %d\n  EOD Wrap Section        : %d\n"+
			"  Validity of EOD         : 0x%04X\n  First CQ Set Number     : %d\n  Physical Position       : 0x%08X\n  CRC                     : %s\n",
			p.WritePassAtEOD, p.ThreadCount, p.RecordCountAtEOD, p.FileMarkCountAtEOD,
			p.EODDataSetNumber, p.EODWrapSection, p.ValidityOfEOD, p.FirstCQSetNumber,
			p.PhysicalPositionEOD, p.CRC)
	}

	if p := d.UnprotectedPages.CartridgeStatus; p != nil {
		h("CARTRIDGE STATUS & TAPEALERT  (page 0x105)")
		fmt.Printf("  Thread Count     : %d\n  Cartridge Status : 0x%04X\n  TapeAlert Flags  : %s\n",
			p.ThreadCount, p.CartridgeStatus, p.TapeAlertRaw)
		if len(p.TapeAlertFlags) == 0 {
			fmt.Printf("  TapeAlert        : (none set)\n")
		} else {
			for _, f := range p.TapeAlertFlags { fmt.Printf("  ⚑  Flag %2d : %s\n", f.Bit, f.Description) }
		}
		fmt.Printf("  CRC              : %s\n", p.CRC)
	}

	if p := d.UnprotectedPages.MechanismRelated; p != nil {
		h("MECHANISM RELATED  (page 0x106)")
		fmt.Printf("  Drive Mfg : %s\n", p.DriveMfg)
		if p.DataHex != "" { fmt.Printf("  Data      : %s\n", p.DataHex) }
	}

	if len(d.UnprotectedPages.UsageInfo) > 0 {
		h("USAGE INFORMATION  (pages 0x108–0x10B, slots 0–3)")
		for _, u := range d.UnprotectedPages.UsageInfo {
			if u.DriveMfg == "" && u.TotalDatasetsWritten == 0 { continue }
			fmt.Printf("\n  Slot %d  (page 0x%03X)  Drive: %s  ID: %s\n", u.SlotIndex, u.PageID, u.DriveMfg, u.DriveID)
			fmt.Printf("    Thread Count                    : %d\n    Datasets Written                : %d\n    Datasets Read                   : %d\n"+
				"    Recovered Write Errors          : %d\n    Recovered Read Errors           : %d\n"+
				"    Unrecovered Write Errors        : %d\n    Unrecovered Read Errors         : %d\n"+
				"    Write Servo Errors              : %d\n    Unrecovered Write Servo Errors  : %d\n"+
				"    Beginning-of-Medium Passes      : %d\n    Middle-of-Tape Passes           : %d\n    CRC                             : %s\n",
				u.ThreadCount, u.TotalDatasetsWritten, u.TotalDatasetsRead,
				u.RecoveredWriteErrors, u.RecoveredReadErrors,
				u.UnrecoveredWriteErrors, u.UnrecoveredReadErrors,
				u.WriteServoErrors, u.UnrecoveredWriteServoErrors,
				u.BOMPasses, u.MOTPasses, u.CRC)
		}
	}

	if len(d.UnprotectedPages.ExtendedPages) > 0 {
		h("EXTENDED PAGES  (pages 0x10C–0x10E)")
		for _, ep := range d.UnprotectedPages.ExtendedPages {
			fmt.Printf("  Page 0x%03X  ver=%d  %s\n", ep.PageID, ep.PageVersion, ep.Note)
			if ep.DataHex != "" { fmt.Printf("    %s\n", ep.DataHex) }
		}
	}

	if p := d.UnprotectedPages.SuspendedAppend; p != nil && len(p.Entries) > 0 {
		h("SUSPENDED APPEND WRITES  (page 0x107)")
		for _, e := range p.Entries { fmt.Printf("  Entry %2d : %s\n", e.Index, e.RawHex) }
	}

	if p := d.UnprotectedPages.TapeDirectory; p != nil {
		h("TAPE DIRECTORY  (page 0x103)")
		fmt.Printf("  FID Write Pass   : %d\n  Active Wraps     : %d / %d\n", p.FIDWritePass, len(p.ActiveWraps), p.TotalWraps)
		if *flagVerbose {
			for _, w := range p.ActiveWraps { fmt.Printf("    Wrap %3d  WP=%-6d  %s\n", w.Index, w.WritePass, w.RawHex) }
		}
	}

	if p := d.UnprotectedPages.AppSpecific; p != nil {
		h("APPLICATION SPECIFIC  (page 0x200)")
		if p.FormatID != "" { fmt.Printf("  Format ID      : %s\n", p.FormatID) }
		if p.LTFSVolumeID != "" { fmt.Printf("  LTFS Volume ID : %s\n", p.LTFSVolumeID) }
		if len(p.EmbeddedMAM) > 0 {
			fmt.Printf("  Embedded MAM attributes:\n")
			for _, a := range p.EmbeddedMAM { printAttr("    ", a) }
		}
	}

	h("SUMMARY")
	if p := d.ProtectedPages.CartridgeMfg; p != nil {
		fmt.Printf("  Cartridge : %s  %s\n  Mfg Date  : %s\n", p.Manufacturer, p.SerialNumber, p.DateOfMfg)
		if p.Generation > 0 {
			extra := ""
			if p.IsWORM { extra = " WORM" } else if p.SupportsPartitions { extra = " (MP)" }
			fmt.Printf("  Type      : LTO-%d%s\n", p.Generation, extra)
		}
	}
	fmt.Printf("  Formatted : %v\n", d.IsFormatted)
	if p := d.ProtectedPages.MediaMfg; p != nil { fmt.Printf("  Media Mfg : %s\n", p.ServowriterMfg) }
	if p := d.UnprotectedPages.EODInfo; p != nil { fmt.Printf("  Threads   : %d\n", p.ThreadCount) }
	if label := findLabel(d); label != "" {
		fmt.Printf("  Label     : %s\n", label)
	} else {
		fmt.Printf("  Label     : (none)\n")
	}
	if barcode := findBarcode(d); barcode != "" { fmt.Printf("  Barcode   : %s\n", barcode) }
	fmt.Printf("  Chip      : %dkbit\n", d.CMInfo.ChipCapacityKbit)
	if p := d.UnprotectedPages.AppSpecific; p != nil && p.LTFSVolumeID != "" {
		fmt.Printf("  LTFS UUID : %s\n", p.LTFSVolumeID)
	}
}

func printHexBlock(indent string, hexStr string) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Printf("%s%s\n", indent, hexStr)
		return
	}
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[i:end]
		hexPart := ""
		for j, by := range chunk {
			if j == 8 {
				hexPart += " "
			}
			hexPart += fmt.Sprintf("%02x ", by)
		}
		ascPart := ""
		for _, by := range chunk {
			if by >= 0x20 && by <= 0x7e {
				ascPart += string(rune(by))
			} else {
				ascPart += "."
			}
		}
		fmt.Printf("%s%04x  %-49s %s\n", indent, i, hexPart, ascPart)
	}
}

func printAttr(indent string, a MAMAttribute) {
	val := a.ValueText
	if val == "" && a.ValueHex != "" {
		val = a.ValueHex
	}
	if a.ID == 0x080C && a.ValueHex != "" {
		fmt.Printf("%s%-40s\n", indent, fmt.Sprintf("%s  %s", a.IDHex, a.Name))
		printHexBlock(indent+"    ", a.ValueHex)
		return
	}
	fmt.Printf("%s%-40s %s\n", indent, fmt.Sprintf("%s  %s", a.IDHex, a.Name), val)
}

func findLabel(d *CMDump) string {
	for _, a := range d.MAMAttributes {
		if a.ID == 0x0803 && a.ValueText != "" { return a.ValueText }
	}
	if p := d.UnprotectedPages.AppSpecific; p != nil {
		for _, a := range p.EmbeddedMAM {
			if a.ID == 0x0803 && a.ValueText != "" { return a.ValueText + "  (from page 0x200)" }
		}
	}
	return ""
}

func findBarcode(d *CMDump) string {
	for _, a := range d.MAMAttributes {
		if a.ID == 0x0806 && a.ValueText != "" { return a.ValueText }
	}
	if p := d.UnprotectedPages.AppSpecific; p != nil {
		for _, a := range p.EmbeddedMAM {
			if a.ID == 0x0806 && a.ValueText != "" { return a.ValueText }
		}
	}
	return ""
}

func cartridgeTypeName(typeHex string) string {
	var raw uint16
	fmt.Sscanf(typeHex, "0x%04X", &raw)
	gen, isWORM := cartridgeGenerationFromType(raw)
	if gen == 0 {
		return typeHex + " (unknown)"
	}
	s := fmt.Sprintf("LTO-%d", gen)
	if isWORM {
		if raw == 0x0031 { s += " Type M" } else { s += " WORM" }
	}
	return fmt.Sprintf("%s (%s)", s, typeHex)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nfc-ltocm-go [flags]\n\nReads an LTO Cartridge Memory tag via NFC and displays its contents.\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// Initialise libnfc
	var context *C.nfc_context
	C.nfc_init(&context)
	if context == nil {
		fmt.Fprintln(os.Stderr, "Error: unable to init libnfc (malloc?)")
		os.Exit(1)
	}
	defer C.nfc_exit(context)

	// Open NFC reader
	pnd = C.ltocm_nfc_open(context)
	if pnd == nil {
		fmt.Fprintln(os.Stderr, "Error: cannot open NFC reader")
		os.Exit(1)
	}
	defer C.nfc_close(pnd)

	// Configure NFC initiator
	if ret := C.nfc_initiator_init(pnd); ret < 0 {
		fmt.Fprintf(os.Stderr, "Error: nfc_initiator_init failed (%d)\n", int(ret)); os.Exit(1)
	}
	if ret := C.nfc_device_set_property_bool(pnd, C.NP_HANDLE_CRC, C.bool(false)); ret < 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot disable CRC handling (%d)\n", int(ret)); os.Exit(1)
	}
	if ret := C.nfc_device_set_property_bool(pnd, C.NP_EASY_FRAMING, C.bool(false)); ret < 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot disable easy framing (%d)\n", int(ret)); os.Exit(1)
	}
	if ret := C.nfc_device_set_property_bool(pnd, C.NP_AUTO_ISO14443_4, C.bool(false)); ret < 0 {
		fmt.Fprintf(os.Stderr, "Error: cannot disable ISO14443-4 auto-switching (%d)\n", int(ret)); os.Exit(1)
	}
	fmt.Printf("NFC reader: %s opened\n", C.GoString(C.nfc_device_get_name(pnd)))

	// Step 1: REQUEST STANDARD  (INIT -> PRESELECT)
	ltoStandard, err := ltocmReqStd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: REQUEST STANDARD failed (%v) – no tag present?\n", err); os.Exit(1)
	}
	fmt.Printf("LTO REQUEST STANDARD: %02X %02X\n", ltoStandard[0], ltoStandard[1])

	var numBlocks int
	switch uint16(ltoStandard[0])<<8 | uint16(ltoStandard[1]) {
	case 0x0001: numBlocks = 127
	case 0x0002: numBlocks = 255
	case 0x0003: numBlocks = 511
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown LTO-CM memory type %02X%02X\n", ltoStandard[0], ltoStandard[1]); os.Exit(1)
	}

	// Step 2: REQUEST SERIAL NUMBER  (PRESELECT -> PRESELECT)
	serialNum, err := ltocmReqSerial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: REQUEST SERIAL NUMBER failed (%v)\n", err); os.Exit(1)
	}
	fmt.Printf("Found LTO-CM tag with s/n %02X:%02X:%02X:%02X:%02X\n",
		serialNum[0], serialNum[1], serialNum[2], serialNum[3], serialNum[4])
	var xorCheck byte
	for _, b := range serialNum[:4] { xorCheck ^= b }
	if xorCheck != serialNum[4] {
		fmt.Fprintln(os.Stderr, "Error: serial number checksum invalid"); os.Exit(1)
	}

	// Step 3: SELECT  (PRESELECT -> COMMAND)
	ack, ackLen, err := ltocmSelect(serialNum)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: SELECT command failed (%v)\n", err); os.Exit(1)
	}
	if ackLen != 1 || ack != ltocmACK {
		fmt.Fprintf(os.Stderr, "Error: SELECT not ACK'd (got %02X len=%d)\n", ack, ackLen); os.Exit(1)
	}

	fmt.Printf("Reading %d LTO-CM blocks...\n", numBlocks)

	// Step 4: Read all blocks into memory
	allData := make([]byte, 0, numBlocks*32)
	blockBuf := make([]byte, 32)
	for block := 0; block < numBlocks; block++ {
		label := fmt.Sprintf("READ BLOCK %d (of %d)", block, numBlocks-1)
		var rxFirst []byte
		if numBlocks <= 255 {
			rxFirst, err = ltocmReadBlk(block)
		} else {
			rxFirst, err = ltocmReadBlkExt(block)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s failed (%v)\n", label, err); os.Exit(1)
		}
		if vErr := validateBlockResponse(rxFirst, label+" (first half)"); vErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", vErr); os.Exit(1)
		}
		copy(blockBuf[0:16], rxFirst[:16])

		rxSecond, err := ltocmReadBlkCnt()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: READ BLOCK CONTINUE block=%d failed (%v)\n", block, err); os.Exit(1)
		}
		if vErr := validateBlockResponse(rxSecond, label+" (second half)"); vErr != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", vErr); os.Exit(1)
		}
		copy(blockBuf[16:32], rxSecond[:16])
		allData = append(allData, blockBuf...)
	}
	fmt.Printf("Read %d bytes from tag.\n", len(allData))

	// Optionally save binary dump
	if *flagOutput != "" {
		if err := os.WriteFile(*flagOutput, allData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot write dump to '%s': %v\n", *flagOutput, err); os.Exit(1)
		}
		fmt.Printf("Raw dump saved → %s\n", *flagOutput)
	}

	// Parse and display
	tagLabel := fmt.Sprintf("NFC [%02X:%02X:%02X:%02X:%02X]",
		serialNum[0], serialNum[1], serialNum[2], serialNum[3], serialNum[4])
	dump, err := parseDumpBytes(allData, tagLabel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parse error: %v\n", err); os.Exit(1)
	}

	if *flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(dump); err != nil {
			fmt.Fprintf(os.Stderr, "json encode: %v\n", err); os.Exit(1)
		}
	} else {
		printDump(dump)
	}
}
