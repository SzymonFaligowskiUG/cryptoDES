package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

var SBox1 []string = []string{
	"101", "010", "001", "110", "011", "100", "111", "000", "001", "100", "110", "010", "000", "111", "101", "011",
}
var SBox2 []string = []string{
	"100", "000", "110", "101", "111", "001", "011", "010", "101", "011", "000", "111", "110", "010", "001", "100",
}

var imageFile = flag.String("image", "none", "encrypt given image, supported file extensions: png, jpeg, gif")

func main() {
	flag.Parse()
	IV := "111011010010"
	key := strToByte("10101010")
	mask := "01323245"

	reader, err := os.Open(*imageFile)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()
	m, _, err := image.Decode(reader)
	if err != nil {
		log.Fatal(err)
	}
	bounds := m.Bounds()
	encryptedImageDes := image.NewRGBA(bounds)
	encryptedImageCBC := image.NewRGBA(bounds)
	done := make(chan struct{})
	go func() {
		previousResults := []uint16{strTo2Byte(IV)}
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				r, g, b, a := m.At(x, y).RGBA()
				toEncrypt := fmt.Sprintf("%08b%08b%08b", uint8(r), uint8(g), uint8(b))
				one := CBC(toEncrypt[:12], key, mask, previousResults[len(previousResults)-1])
				previousResults = append(previousResults, strTo2Byte(one))
				two := CBC(toEncrypt[:12], key, mask, previousResults[len(previousResults)-1])
				previousResults = append(previousResults, strTo2Byte(two))
				encrypted := fmt.Sprintf("%s%s", one, two)
				er := strToByte(encrypted[:8])
				eg := strToByte(encrypted[8:16])
				eb := strToByte(encrypted[16:])
				encryptedImageCBC.Set(x, y, color.RGBA{R: er, G: eg, B: eb, A: uint8(a)})
			}
		}
		saveImage(encryptedImageCBC, *imageFile, "DESCBC")

		done <- struct{}{}
	}()

	go func() {
		wg := sync.WaitGroup{}
		for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
			for x := bounds.Min.X; x < bounds.Max.X; x++ {
				wg.Add(1)
				go func(x int, y int) {
					defer wg.Done()
					r, g, b, a := m.At(x, y).RGBA()
					toEncrypt := fmt.Sprintf("%08b%08b%08b", uint8(r), uint8(g), uint8(b))
					encrypted := fmt.Sprintf("%s%s", encryptBlock(toEncrypt[:12], key, mask), encryptBlock(toEncrypt[12:], key, mask))
					er := strToByte(encrypted[:8])
					eg := strToByte(encrypted[8:16])
					eb := strToByte(encrypted[16:])
					encryptedImageDes.Set(x, y, color.RGBA{R: er, G: eg, B: eb, A: uint8(a)})
				}(x, y)
			}
		}
		wg.Wait()
		saveImage(encryptedImageDes, *imageFile, "DES")
		done <- struct{}{}
	}()

	<-done
	<-done

}

func saveImage(image image.Image, prevName, encryptionName string) {
	nameSplit := strings.Split(prevName, ".")
	extension := nameSplit[len(nameSplit)-1]
	newName := nameSplit[len(nameSplit)-2] + encryptionName + "." + extension
	switch extension {
	case "png":
		f, _ := os.Create(newName)
		png.Encode(f, image)
	case "jepg":
		f, _ := os.Create(newName)
		jpeg.Encode(f, image, nil)
	case "gif":
		f, _ := os.Create(newName)
		gif.Encode(f, image, nil)
	}

}

func CBC(allBytes string, key uint8, mask string, previousResult uint16) string {
	byteTextBlockOne := previousResult ^ strTo2Byte(allBytes)
	dezznuts := fmt.Sprintf("%016b", byteTextBlockOne)[4:]

	r := encryptBlock(dezznuts, key, mask)
	return r
}

func encryptBlock(text string, key uint8, mask string) string {
	R := make([]uint8, 8)
	L := make([]uint8, 9)
	R[0] = strToByte(text[6:])
	L[0] = strToByte(text[:6])
	L[1] = R[0]
	for i := range 8 {
		if i == 7 {
			one := fmt.Sprintf("%08b", R[6])[2:]
			two := fmt.Sprintf("%08b", L[8])[2:]
			return fmt.Sprintf("%s%s", two, one)
		}
		Rx := E(R[i], mask)
		shiftedKey := getKey(key, i+1, false)
		block := L[i] ^ F(Rx^shiftedKey)
		R[i+1] = block
		L[i+2] = block
	}

	return ""

}

func E(text uint8, mask string) uint8 {
	textStr := fmt.Sprintf("%08b", text)

	var maskedText string
	for _, rawConvIdx := range strings.Split(mask, "") {
		idx, _ := strconv.Atoi(rawConvIdx)
		bit, _ := strconv.Atoi(string(textStr[idx+2]))
		maskedText += strconv.Itoa(bit)
	}
	return strToByte(maskedText)

}

func getKey(key uint8, start int, reverse bool) uint8 {
	keyStr := fmt.Sprintf("%08b", key)
	if reverse {
		keyStr = Reverse(keyStr)
	}
	keySplit := strings.Split(keyStr, "")
	newKey := ""
	for i := range len(keySplit) {
		pick := (i + start) % len(keySplit)
		newKey += keySplit[pick]
	}
	return strToByte(newKey)
}

func F(sBoxMatch uint8) uint8 {
	matchString := fmt.Sprintf("%08b", sBoxMatch)
	sBox1Idx := strToByte(matchString[:4])
	sBox2Idx := strToByte(matchString[4:])

	return strToByte(strings.Join([]string{SBox1[sBox1Idx], SBox2[sBox2Idx]}, ""))
}

func strToByte(str string) uint8 {
	var byted uint8
	for n, rawBite := range strings.Split(Reverse(str), "") {
		bit, _ := strconv.Atoi(rawBite)
		byted |= uint8(bit) << uint8(n)
	}
	return byted
}

func strTo2Byte(str string) uint16 {
	var byted uint16
	for n, rawBite := range strings.Split(Reverse(str), "") {
		bit, _ := strconv.Atoi(rawBite)
		byted |= uint16(bit) << uint16(n)
	}
	return byted
}

func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}
