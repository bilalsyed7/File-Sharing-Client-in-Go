package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//used to store all the keys to decrypt a single file
//FileKeys structs are contained within the User struct
type FileKeys struct {
	//contains:
	//tree of individuals file is shared to
	//*encryption key
	//*HMAC
	//*datastore key
	EKey []byte
	HMACKey []byte
	FileStruct userlib.UUID
}

type File struct {
	Filename string
	Files []userlib.UUID
}

// The structure definition for a user record
type User struct {
	Username string
	Password string

	//HMAC
	HMAC []byte

	//RSA signature Key
	RSA userlib.PKEDecKey

	//Digital Sign Key
	DS userlib.DSSignKey
	//Hashmap that maps keys to unique files for those specific files, user should also store all the keys to decrypt
	//the file
	Files map[string]FileKeys
	//Hashmap for the shared keys

	//files user shares with others
	SharedFiles map[string]uuid.UUID

	//files received from others
	ReceivedFiles map[string]AccessRecord

	//encryption keys for sharing records, maps key: string(filename+usersharedwith), val:encryptionKeyforsharingrecord
	RecordKeys map[string][]byte

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type Stored struct {
	HMAC []byte
	EncryptedM []byte
}

//helper function to pad file data to AES block size so symmetric encryption can work
func padFile(data []byte) (padData []byte) {
	if len(data) % userlib.AESBlockSize != 0{
		//padding
		if len(data) < userlib.AESBlockSize {
			pad := userlib.AESBlockSize - len(data)
			for i := 0; i < pad; i++ {
				data = append(data, byte(pad))
			}
		} else {
			temp := userlib.AESBlockSize
			for temp < len(data){
				temp += userlib.AESBlockSize
			}
			pad := temp - len(data)
			for i := 0; i < pad; i++ {
				data = append(data, byte(pad))
			}
		}
	} else {
		pad := 0
		for i := 0; i < userlib.AESBlockSize; i++ {
			data = append(data, byte(pad))
		}
	}
	return data
}
func dePad(data []byte) (padData []byte) {
	pad := data[len(data) - 1]
	if pad == 0 {
		data = data[:len(data) - userlib.AESBlockSize]
	} else {
		data = data[:len(data) - int(pad)]
	}
	return data
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	userdata.Username = username
	userdata.Password = password

	//map for all the files
	hm := make(map[string]FileKeys)
	userdata.Files = hm

	//map for sharedFiles
	sf := make(map[string]userlib.UUID)
	userdata.SharedFiles = sf

	//map for receivedFiles
	//rf := make(map[string]AccessRecord)
	//userdata.ReceivedFiles = rf

	//map for recordKeys
	rk := make(map[string][]byte)
	userdata.RecordKeys = rk

	//RSA key
	//generate public encryption keys and digital signature keys
	publicEncryptionKey, publicDecryptionKey, _ := userlib.PKEKeyGen()
	digitalPrivateKey, digitalPublicKey, _ := userlib.DSKeyGen()

	//set users private RSA key and private DS Key
	userdata.RSA = publicDecryptionKey
	userdata.DS = digitalPrivateKey

	//check if username already exists
	_, duplicate := userlib.KeystoreGet(username + "PK")
	if (duplicate) {
		return nil, errors.New("This user already exists")
	}

	//set users public RSA key
	userlib.KeystoreSet(username + "PK", publicEncryptionKey)
	userlib.KeystoreSet(username + "DS", digitalPublicKey)

	//create salt and generate the key using this salt
	salt := userlib.Hash([]byte(username + password))

	//userKey is the key used to store the user struct in Datastore
	var userKey []byte
	userKey = userlib.Argon2Key([]byte(password), salt[:16], uint32(userlib.AESKeySize))

	//UUID should be userKEy
	new_UUID, _ := uuid.FromBytes([]byte(userKey))

	//data should be marshaled version of the user struct
	data, _ := json.Marshal(userdata)

	//padding for userstruct, must be multiple of AESBlockSize
	data = padFile(data)

	//generate IV
	IV := userlib.RandomBytes(userlib.AESKeySize)

	//generate key for Symmetric encryption
	salt2 := userlib.Hash([]byte(password + username))
	encryptionKey := userlib.Argon2Key([]byte(password), salt2[:16], uint32(userlib.AESKeySize))

	//encrypt the user struct
	encryptedMessage := userlib.SymEnc(encryptionKey, IV, data)

	//Get the HMAC key
	hashKey := userlib.Argon2Key([]byte(password), salt2[16:], uint32(userlib.AESKeySize))
	User_HMAC, _ := userlib.HMACEval(hashKey, []byte(encryptedMessage))

	//store everything in the datastore
	//make a slice containing HMAC, and encrypted struct
	//then marshal this 2D slice so it converts into []byte format
	var output Stored
	output.HMAC = User_HMAC
	output.EncryptedM = encryptedMessage

	//output := [][]byte{User_HMAC, encryptedMessage}
	marshalOutput, _ := json.Marshal(output)

	userlib.DatastoreSet(new_UUID, marshalOutput)
	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.

func GetUser(username string, password string) (userdataptr *User, err error) {
	/*
		var userdata User
		userdataptr = &userdata
	*/
	var userdata User
	userdataptr = &userdata

	salt := userlib.Hash([]byte(username + password))

	//userKey is the key used to store the user struct in Datastore
	userKey := userlib.Argon2Key([]byte(password), salt[:16], uint32(userlib.AESKeySize))

	//UUID should be unique identifier computed from userKEy
	Uuid, _ := uuid.FromBytes([]byte(userKey))

	//if valid user, gets data slice containing 0: user HMAC, 1: Encrypted user pointer
	marshData, valid := userlib.DatastoreGet(Uuid)

	//if user/password is invalid
	if valid != true {
		return nil, errors.New("Invalid User/Password")
	}

	//unmarshal the 2D slice containing user's HMAC and encrypted struct
	var input Stored
	err = json.Unmarshal(marshData, &input)
	if err != nil {
		return nil, errors.New("Invalid User/Password")
	}
	encryptedMessage := input.EncryptedM
	inputHMAC := input.HMAC

	//encrypted/marshalled struct at 1 index of dataSlice
	//encryptedMessage := dataSlice[1]

	//compute the key you will use to try to decrypt the message
	salt2 := userlib.Hash([]byte(password + username))
	decryptionKey := userlib.Argon2Key([]byte(password), salt2[:16], uint32(userlib.AESKeySize))

	//compute what the HMAC should be given username / password
	hashKey := userlib.Argon2Key([]byte(password), salt2[16:], uint32(userlib.AESKeySize))
	computedHmac, _ := userlib.HMACEval(hashKey, []byte(encryptedMessage))


	//decrypt the marshalled struct
	//encrypted message should be of a size multiple of AES block size but maybe we should check????
	//function symdec returns error if not aes block size
	marshMessage := userlib.SymDec(decryptionKey, encryptedMessage)

	//reassign user to the unmarshalled marshalled struct, making userdataptr point to appropriate struct
	marshMessage = dePad(marshMessage)
	err = json.Unmarshal(marshMessage, &userdataptr)
	if err != nil {
		return nil, errors.New("Invalid User/Password")
	}
	//check if HMACs are equal so that there's no corruption
	//throw an error if anything has been tampered with
	if (!userlib.HMACEqual(inputHMAC, computedHmac)) {
		return userdataptr, errors.New("HMAC has been altered, and so message has been corrupted")
	}
	return userdataptr, nil
}

//HAVE TO CHECK IF FILES HAVEN'T BEEN TAMPERED WITH / CHECK HMAC STUFF + same goes for loadfile!
func (userdata *User) DeleteFile(eKey []byte, uuid userlib.UUID) (err error) {
	//get the file struct
	//get the file struct from the datastore
	encryptedHeader, _ := userlib.DatastoreGet(uuid)
	var store Stored
	json.Unmarshal(encryptedHeader, &store)

	file_header := userlib.SymDec(eKey, store.EncryptedM)
	file_header = dePad(file_header)

	var header File
	//unmarshal the data structure
	json.Unmarshal(file_header, &header)

	//loop through the File struct list and get all the blocks of the file
	for _, fileUUID := range header.Files {
		//CHECK HMAC STUFF
		userlib.DatastoreDelete(fileUUID)
	}
	return nil
}
// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
//EDIT TO HANDLE OVERWRITES, MAKE DATASTORE KEYS NONRANDOM (SO SAME FILENAME/USER -> SAME DS KEY/VAL PAIR)
//IN PROGRESS, very tedious
func (userdata *User) StoreFile(filename string, data []byte) {

	//trying to split up storeFile into different cases, if the file has already been stored, or if the file has already been received (in both cases
	//overwrite the file with new data), or if file doesn't exist (normal store file)
	if myFile, ok := userdata.Files[filename]; ok {
		//get fileStruct info from fileKeys, then find and decrypt file struct
		fileStructuuid := myFile.FileStruct
		eKey := myFile.EKey
		hmacKey := myFile.HMACKey
		cipherStored, _ := userlib.DatastoreGet(fileStructuuid)
		var checkAuth Stored
		_ = json.Unmarshal(cipherStored, &checkAuth)

		marshStored := userlib.SymDec(eKey, checkAuth.EncryptedM)
		marshStored =  dePad(marshStored)

		fileHMAC, _ := userlib.HMACEval(hmacKey, checkAuth.EncryptedM)
		//if the current file struct has been tampered with, will have to make a new one through the !ok2 !ok3 case
		if !userlib.HMACEqual(fileHMAC, checkAuth.HMAC) {
			userlib.DatastoreDelete(fileStructuuid)
			delete(userdata.Files, filename)

			//normal case where you keep going to overwrite old file data, with new file data we create
		} else {
			//encrypt the file first
			//need datastore key, HMAC, and encryption key
			//encryption key
			salt := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))
			encryptionKey := userlib.Argon2Key([]byte(userdata.Password), salt[:16], uint32(userlib.AESKeySize))
			IV := userlib.RandomBytes(userlib.AESKeySize)

			//pad data file before using symEnc!!!
			data = padFile(data)

			//encrypted file data, properly padded
			encryptedFile := userlib.SymEnc(encryptionKey, IV, data)

			//HMAC
			salt2 := userlib.Hash([]byte(filename + userdata.Password + userdata.Username))
			HashKey :=userlib.Argon2Key([]byte(userdata.Password), salt2[:16], uint32(userlib.AESKeySize))
			fileHMAC, _ := userlib.HMACEval(HashKey, encryptedFile)
			dsKey := userlib.RandomBytes(userlib.AESKeySize)
			dsKey_UUID,_ := uuid.FromBytes(dsKey)

			//store the file in the datastore
			//datastore key -> (HMAC, encryptedFile plaintext)
			output := Stored{fileHMAC, encryptedFile}
			marshalFile, _ := json.Marshal(output)
			userlib.DatastoreSet(dsKey_UUID, marshalFile)

			//delete the old file data, so you can overwrite with fresh data
			_ = userdata.DeleteFile(eKey, fileStructuuid)

			//decrypt and unmarshal file struct from stored struct
			cipherFilestruct := checkAuth.EncryptedM
			marshFilestruct := userlib.SymDec(eKey, cipherFilestruct)
			marshFilestruct = dePad(marshFilestruct)
			var fileStruct File
			_ = json.Unmarshal(marshFilestruct, &fileStruct)

			//reassign current map to a new map with just the uuid of the new file (thus garbage collected old values of the map)
			fileStruct.Files = []userlib.UUID{dsKey_UUID}

			//reencrypt file struct and store in datastore
			//encrypt the File struct with the same keys used to encrypt the file plaintext
			marshalFileStruct, _ := json.Marshal(fileStruct)

			//pad marshalled file struct prior to encryption
			marshalFileStruct = padFile(marshalFileStruct)

			//encrypt filestruct + compute HMAC + datastore key for file struct
			encryptedFileStruct := userlib.SymEnc(encryptionKey, IV, marshalFileStruct)
			fileStructHMAC, _ := userlib.HMACEval(HashKey, encryptedFileStruct)

			output = Stored{fileStructHMAC, encryptedFileStruct}
			storedFileStruct, _ := json.Marshal(output)
			userlib.DatastoreSet(fileStructuuid, storedFileStruct)
			//now the updated file struct has been reencrypted / restored from where it came
		}
	} else if _, ok := userdata.ReceivedFiles[filename]; ok {
		//if the file is in received files and the user still has access to it, then you want to overwrite that file with new
		//file data, which is received by decrypting the sharing record, and then getting the proper pointer to the file struct
		if userdata.stillShared(filename) {
			//get location of sharing record and decrypt it (stillShared already checks if properly encrypted, abstracted away to that function)
			//first get user's accessstruct values to find and properly decrypt the sharing record
			accessRec := userdata.ReceivedFiles[filename]
			shareKey := accessRec.Key
			shareLoc := accessRec.Recordlocation
			shareHmac := accessRec.RecordHMAC

			//now get the sharing record, verify if it hasn't been tampered with through hmac verification, then decrypt if proper
			checkShare, _ := userlib.DatastoreGet(shareLoc)
			var checkStore Stored
			_ = json.Unmarshal(checkShare, &checkStore)
			//if the the sharing record has been tampered with, going to have to delete malicious sharing record, and follow through with the !ok2 and !ok3 case
			if !userlib.HMACEqual(shareHmac, checkStore.HMAC) {
				userlib.DatastoreDelete(shareLoc)
				delete(userdata.ReceivedFiles, filename)
				//else proceed as normal, and decrypt the proper sharing record, store new file data with same keys/hmac sharing record has
			} else {
				cipherShare := checkStore.EncryptedM
				marshShare := userlib.SymDec(shareKey, cipherShare)
				marshShare = dePad(marshShare)
				var shareRec SharingRecord
				_ = json.Unmarshal(marshShare, &shareRec)

				//check if the fileStruct that the sharing record points to hasn't been tampered with, else proceed with !ok2 and !ok3 case, storing a new file
				marshStore, _ := userlib.DatastoreGet(shareRec.Datalocation)
				var checkStore Stored
				_ = json.Unmarshal(marshStore, &checkStore)
				//fileStruct has been tampered with, delete sharing record on datastore and access record in userdata, create new file struct/file w !ok2 and !ok3 case
				expectedFShmac, _ := userlib.HMACEval(shareRec.HmacKey, checkStore.EncryptedM)
				if !userlib.HMACEqual(expectedFShmac, checkStore.HMAC) {
					userlib.DatastoreDelete(shareLoc)
					delete(userdata.ReceivedFiles, filename)
					//else proceed as normal, proper sharing record and proper file struct, so create a file, store it with hmac in sharing record and
					//encrypted with key in sharing record, then update file struct by deleting old data and updating with new
				} else {
					//encrypt the file first
					//need datastore key, HMAC, and encryption key
					//encryption key = key in shareRec = owner's encryption key for files/file struct
					encryptionKey := shareRec.Ekey
					IV := userlib.RandomBytes(userlib.AESKeySize)

					//pad data file before using symEnc!!!
					data = padFile(data)

					//encrypted file data, properly padded
					encryptedFile := userlib.SymEnc(encryptionKey, IV, data)

					//use shareRec hmac key to calculate file hmac
					fileHMAC, _ := userlib.HMACEval(shareRec.HmacKey, encryptedFile)
					dsKey := userlib.RandomBytes(userlib.AESKeySize)
					dsKey_UUID,_ := uuid.FromBytes(dsKey)

					//store the file in the datastore
					//datastore key -> (HMAC, encryptedFile plaintext)
					output := Stored{fileHMAC, encryptedFile}
					marshalFile, _ := json.Marshal(output)
					userlib.DatastoreSet(dsKey_UUID, marshalFile)

					//delete current file map data, decrypt file struct, update file map data with new stored file block
					//check error!
					fileStructuuid := shareRec.Datalocation
					_ = userdata.DeleteFile(encryptionKey, fileStructuuid)

					marshFile := userlib.SymDec(shareRec.Ekey, checkStore.EncryptedM)
					marshFile = dePad(marshFile)
					var sharedFile File
					_ = json.Unmarshal(marshFile, &sharedFile)
					sharedFile.Files = []userlib.UUID{dsKey_UUID}

					//reencrypt file struct and store in datastore
					//encrypt the File struct with the same keys used to encrypt the file plaintext
					marshalFileStruct, _ := json.Marshal(sharedFile)

					//pad marshalled file struct prior to encryption
					marshalFileStruct = padFile(marshalFileStruct)

					//encrypt filestruct + compute HMAC + datastore key for file struct
					encryptedFileStruct := userlib.SymEnc(encryptionKey, IV, marshalFileStruct)
					fileStructHMAC, _ := userlib.HMACEval(shareRec.HmacKey, encryptedFileStruct)

					output = Stored{fileStructHMAC, encryptedFileStruct}
					storedFileStruct, _ := json.Marshal(output)
					userlib.DatastoreSet(fileStructuuid, storedFileStruct)
					//now the updated file struct has been reencrypted / restored from where it came
				}
			}

		} else {
			//built in function that deletes the record of access to a revoked file
			delete(userdata.ReceivedFiles, filename)
		}
	}
	_, ok2 := userdata.Files[filename]
	_, ok3 := userdata.ReceivedFiles[filename]
	//if file doesn't already exist (in user's files or user's received files)
	if !ok2 && !ok3 {

		//encrypt the file first
		//need datastore key, HMAC, and encryption key
		//encryption key
		salt := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))
		encryptionKey := userlib.Argon2Key([]byte(userdata.Password), salt[:16], uint32(userlib.AESKeySize))
		IV := userlib.RandomBytes(userlib.AESKeySize)

		//pad data file before using symEnc!!!
		data = padFile(data)

		//encrypted file data, properly padded
		encryptedFile := userlib.SymEnc(encryptionKey, IV, data)

		//HMAC
		salt2 := userlib.Hash([]byte(filename + userdata.Password + userdata.Username))
		HashKey := userlib.Argon2Key([]byte(userdata.Password), salt2[:16], uint32(userlib.AESKeySize))
		fileHMAC, _ := userlib.HMACEval(HashKey, encryptedFile)
		dsKey := userlib.RandomBytes(userlib.AESKeySize)
		dsKey_UUID,_ := uuid.FromBytes(dsKey)

		//store the file in the datastore
		//datastore key -> (HMAC, encryptedFile plaintext)
		output := Stored{fileHMAC, encryptedFile}
		marshalFile, _ := json.Marshal(output)
		userlib.DatastoreSet(dsKey_UUID, marshalFile)

		//set the file struct, this struct keeps track of the filename and a list of UUID of all the file chunks
		//this will help us for appending files and for sharing
		var file File
		file.Filename = filename
		//only contains the UUID of the first block we stored
		file.Files = []userlib.UUID{dsKey_UUID}

		//encrypt the File struct with the same keys used to encrypt the file plaintext
		marshalFileStruct, _ := json.Marshal(file)

		//pad marshalled file struct prior to encryption
		marshalFileStruct = padFile(marshalFileStruct)

		//encrypt filestruct + compute HMAC + datastore key for file struct
		encryptedFileStruct := userlib.SymEnc(encryptionKey, IV, marshalFileStruct)
		fileStructHMAC, _ := userlib.HMACEval(HashKey, encryptedFileStruct)
		dsKey = userlib.RandomBytes(userlib.AESKeySize)
		fileStructDSKey,_:= uuid.FromBytes(dsKey)

		output = Stored{fileStructHMAC, encryptedFileStruct}
		storedFileStruct, _ := json.Marshal(output)
		userlib.DatastoreSet(fileStructDSKey, storedFileStruct)

		//setting the variables in FileKeys struct
		var fk FileKeys
		fk.EKey = encryptionKey
		fk.HMACKey = HashKey
		fk.FileStruct = fileStructDSKey

		//map the filename to the filestruct
		userdata.Files[filename] = fk
	}
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
//DS KEYS SHOULDN'T BE RANDOM
//HAVE TO CHECK IF FILE EXISTS
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	//case where the file is in the user's stored files
	if fileKeys, ok := userdata.Files[filename]; ok {
		//encrypt the file block and add onto the datastore
		//encrypt the file first
		//need datastore key, HMAC, and encryption key
		//encryption key

		salt := userlib.Hash([]byte(userdata.Username + userdata.Password + filename))
		encryptionKey := userlib.Argon2Key([]byte(userdata.Password), salt[:16], uint32(userlib.AESKeySize))
		IV := userlib.RandomBytes(userlib.AESKeySize)

		data = padFile(data)
		encryptedFile := userlib.SymEnc(encryptionKey, IV, data)

		//HMAC
		salt2 := userlib.Hash([]byte(filename + userdata.Password + userdata.Username))
		HashKey :=userlib.Argon2Key([]byte(userdata.Password), salt2[:16], uint32(userlib.AESKeySize))
		fileHMAC, _ := userlib.HMACEval(HashKey, encryptedFile)

		//datastore key
		dsKey := userlib.RandomBytes(userlib.AESKeySize)
		dsKey_UUID,_ := uuid.FromBytes(dsKey)

		//store the file in the datastore
		//datastore key -> (HMAC, encryptedFile plaintext)
		output := Stored{fileHMAC, encryptedFile}
		marshalFile, _ := json.Marshal(output)
		userlib.DatastoreSet(dsKey_UUID, marshalFile)

		//get the file struct UUID
		file_header_UUID := fileKeys.FileStruct
		//get the decryption key for the file struct
		//eKey := fileKeys.EKey; doesn't seem to be useful since encryptionKey (calculated above) should = eKey
		//get the hmac of the file struct
		hmacKey := fileKeys.HMACKey

		//get the encrypted store struct from the datastore, decrypt it, and check if the hmac is good
		storedBytes, _ := userlib.DatastoreGet(file_header_UUID)
		var checkStored Stored
		_ = json.Unmarshal(storedBytes, &checkStored)
		hmac,_ := userlib.HMACEval(hmacKey, checkStored.EncryptedM)
		if !userlib.HMACEqual(hmac, checkStored.HMAC) {
			return errors.New("The file struct storing the map of file data locations has been tampered with")
		}

		//hmac is good, so continue with getting the file struct
		cipherFilestruct := checkStored.EncryptedM
		marshFilestruct := userlib.SymDec(encryptionKey, cipherFilestruct)
		marshFilestruct = dePad(marshFilestruct)

		var header File
		//unmarshal the data structure
		json.Unmarshal(marshFilestruct, &header)

		header.Files = append(header.Files, dsKey_UUID)

		//encrypt the File Struct again
		marshalFileStruct, _ := json.Marshal(header)
		marshalFileStruct = padFile(marshalFileStruct)
		encryptedFileStruct := userlib.SymEnc(encryptionKey, IV, marshalFileStruct)

		fileStructHMAC, _ := userlib.HMACEval(HashKey, encryptedFileStruct)

		output = Stored{fileStructHMAC, encryptedFileStruct}
		storedFileStruct, _ := json.Marshal(output)
		userlib.DatastoreSet(file_header_UUID, storedFileStruct)

		ptr := userdata.Files[filename]
		ptr.HMACKey = HashKey

		ptr2 := userdata
		ptr2.Files[filename] = ptr

		//case where file is in user's received files (user has been shared the file from someone else)
	} else if _, ok2 := userdata.ReceivedFiles[filename]; ok2 {
		//case where user still has access to the file
		if userdata.stillShared(filename) {
			//get location of sharing record and decrypt it (stillShared already checks if properly encrypted, abstracted away to that function)
			//first get user's accessstruct values to find and properly decrypt the sharing record
			accessRec := userdata.ReceivedFiles[filename]
			shareKey := accessRec.Key
			shareLoc := accessRec.Recordlocation
			shareHmac := accessRec.RecordHMAC
			//now get the sharing record, verify if it hasn't been tampered with through hmac verification, then decrypt if proper
			checkShare, _ := userlib.DatastoreGet(shareLoc)
			var checkStore Stored
			_ = json.Unmarshal(checkShare, &checkStore)

			//if the the sharing record has been tampered with, going to have to delete malicious sharing record and return error
			if !userlib.HMACEqual(shareHmac, checkStore.HMAC) {
				userlib.DatastoreDelete(shareLoc)
				delete(userdata.ReceivedFiles, filename)
				return errors.New("sharing record has been tampered with, so user doesn't have access to the file anymore")

				//else proceed as normal, and decrypt the proper sharing record, append new file data with same keys/hmac sharing record has
			} else {
				cipherShare := checkStore.EncryptedM
				marshShare := userlib.SymDec(shareKey, cipherShare)
				marshShare = dePad(marshShare)
				var shareRec SharingRecord
				_ = json.Unmarshal(marshShare, &shareRec)

				//check if the fileStruct that the sharing record points to hasn't been tampered with, else return error
				marshStore, _ := userlib.DatastoreGet(shareRec.Datalocation)
				var checkStore Stored
				_ = json.Unmarshal(marshStore, &checkStore)
				shareHMAC,_ := userlib.HMACEval(shareRec.HmacKey, checkStore.EncryptedM)

				//fileStruct has been tampered with, delete sharing record on datastore and access record in userdata, create new file struct/file w !ok2 and !ok3 case
				if !userlib.HMACEqual(shareHMAC, checkStore.HMAC) {
					userlib.DatastoreDelete(shareLoc)
					delete(userdata.ReceivedFiles, filename)
					return errors.New("file struct has been tampered with, so user no longer has access to the file struct")

					//else proceed as normal, proper sharing record and proper file struct, so create a file, store it with hmac in sharing record and
					//encrypted with key in sharing record, then update file struct by deleting old data and updating with new
				} else {
					//encrypt the file first
					//need datastore key, HMAC, and encryption key
					//encryption key = key in shareRec = owner's encryption key for files/file struct
					encryptionKey := shareRec.Ekey
					IV := userlib.RandomBytes(userlib.AESKeySize)
					//pad data file before using symEnc!!!
					data = padFile(data)

					//encrypted file data, properly padded
					encryptedFile := userlib.SymEnc(encryptionKey, IV, data)

					//use shareRec hmac key to calculate file hmac
					fileHMAC, _ := userlib.HMACEval(shareRec.HmacKey, encryptedFile)
					dsKey := userlib.RandomBytes(userlib.AESKeySize)
					dsKey_UUID,_ := uuid.FromBytes(dsKey)

					//store the file in the datastore
					//datastore key -> (HMAC, encryptedFile plaintext)
					output := Stored{fileHMAC, encryptedFile}
					marshalFile, _ := json.Marshal(output)
					userlib.DatastoreSet(dsKey_UUID, marshalFile)

					//append new data's uuid to the end of the file map
					//check error!

					fileStructuuid := shareRec.Datalocation
					marshFile := userlib.SymDec(shareRec.Ekey, checkStore.EncryptedM)
					marshFile = dePad(marshFile)

					var sharedFile File
					_ = json.Unmarshal(marshFile, &sharedFile)
					sharedFile.Files = append(sharedFile.Files, dsKey_UUID)

					//reencrypt file struct and store in datastore
					//encrypt the File struct with the same keys used to encrypt the file plaintext
					marshalFileStruct, _ := json.Marshal(sharedFile)

					//pad marshalled file struct prior to encryption
					marshalFileStruct = padFile(marshalFileStruct)

					//encrypt filestruct + compute HMAC + datastore key for file struct
					encryptedFileStruct := userlib.SymEnc(encryptionKey, IV, marshalFileStruct)
					fileStructHMAC,_ := userlib.HMACEval(shareRec.HmacKey, encryptedFileStruct)

					output = Stored{fileStructHMAC, encryptedFileStruct}
					storedFileStruct, _ := json.Marshal(output)
					userlib.DatastoreSet(fileStructuuid, storedFileStruct)
					//now the updated file struct has been reencrypted / restored from where it came
				}
			}
			//case where user's access to the file has been revoked
		} else {
			//built in function that deletes the record of access to a revoked file
			delete(userdata.ReceivedFiles, filename)
			return errors.New("user no longer has access to this file")
		}
		//case where the user does not have the file
	} else {
		return errors.New("file does not exist for this user")
	}
	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	var output []byte
	if fileKeys, ok := userdata.Files[filename]; ok {
		//get the file struct
		//get the file struct UUID first
		file_header_UUID := fileKeys.FileStruct

		decryptionKey := fileKeys.EKey

		//get the file struct from the datastore
		file_header, invalid := userlib.DatastoreGet(file_header_UUID)

		if invalid == false {
			return nil, errors.New("file struct could not be found")
		}

		var stored Stored

		//unmarshal the data structure
		json.Unmarshal(file_header, &stored)
		//verify the hmac for the fileKeys
		storedHmac := stored.HMAC
		storedEncrypted := stored.EncryptedM

		//check the HMAC of the encrypted Message with that of the one in stored

		salt2 := userlib.Hash([]byte(filename + userdata.Password + userdata.Username))
		HashKey :=userlib.Argon2Key([]byte(userdata.Password), salt2[:16], uint32(userlib.AESKeySize))


		fileStructHMAC, _ := userlib.HMACEval(HashKey, storedEncrypted)
		if !userlib.HMACEqual(storedHmac,fileStructHMAC ) {
			return nil, errors.New("HMAC has been altered, and so message has been corrupted")
		}
		//depad the file struct
		//decrypt the file struct
		decryptedfileStruct := userlib.SymDec(decryptionKey, storedEncrypted)
		storedEncrypted = dePad(decryptedfileStruct)

		var fileStruct File
		json.Unmarshal(storedEncrypted, &fileStruct)

		var output []byte

		//loop through the File struct list and get all the blocks of the file

		for i, fileUUID := range fileStruct.Files {
			fileBlock, _ := userlib.DatastoreGet(fileUUID)
			i = i

			var tempFile Stored
			//unmarshal and decrypt the File
			json.Unmarshal(fileBlock, &tempFile)

			//check HMAC
			fileHMAC, _ := userlib.HMACEval(HashKey, tempFile.EncryptedM)

			if !userlib.HMACEqual(tempFile.HMAC, fileHMAC ) {
				return nil, errors.New("HMAC has been altered, and so message has been corrupted")
			}

			//decrypt the file
			fileEncrypted := userlib.SymDec(decryptionKey, tempFile.EncryptedM)
			decryptedFile := dePad(fileEncrypted)

			//append onto output byte
			output = append(output, decryptedFile...)
		}
		return output, nil
	} else if accessRec, ok := userdata.ReceivedFiles[filename]; ok {
		if userdata.stillShared(filename) {
			shareLoc := accessRec.Recordlocation
			sharedRecord, err := userlib.DatastoreGet(shareLoc)
			//shareRecord has gone missing, delete accessRecord since the mapped to share is not at proper location
			if !err {
				delete(userdata.ReceivedFiles, filename)
				return nil, errors.New("Error has occurred, shareRecord is lo longer there")
			}

			var sharedStoredstruct Stored

			//unmarshal the stored struct that holds the encrypted sharing record
			json.Unmarshal(sharedRecord, &sharedStoredstruct)

			if !userlib.HMACEqual(accessRec.RecordHMAC, sharedStoredstruct.HMAC) {
				userlib.DatastoreDelete(shareLoc)
				delete(userdata.ReceivedFiles, filename)
				return nil, errors.New("HMAC has been altered, and so message has been corrupted, therefore delete sharing record and access record")
			}
			//you know sharing record hasn't been tampered with, so decrypt and unmarshal it
			cipherShare := sharedStoredstruct.EncryptedM
			marshShare := userlib.SymDec(accessRec.Key, cipherShare)
			marshShare = dePad(marshShare)

			var sharedR SharingRecord
			json.Unmarshal(marshShare, &sharedR)

			//use sharing Record to get the file struct
			fileStructloc := sharedR.Datalocation
			fileStruct, err := userlib.DatastoreGet(fileStructloc)

			if !err {
				userlib.DatastoreDelete(shareLoc)
				delete(userdata.ReceivedFiles, filename)
				return nil, errors.New("Error has occurred, the file struct does not exist at this location anymore, so the sharing record is invalid")
			}

			var storedFilestruct Stored
			json.Unmarshal(fileStruct, &storedFilestruct)

			//sharedHMAC,_ := userlib.HMACEval(sharedR.HmacKey, storedFilestruct.EncryptedM)
			checkHMAC,_ := userlib.HMACEval(sharedR.HmacKey, storedFilestruct.EncryptedM)
			//check the hmac for the file struct, if invalid then delete shareRecord and access record since they're now useless
			if !userlib.HMACEqual(checkHMAC, storedFilestruct.HMAC) {
				userlib.DatastoreDelete(shareLoc)
				delete(userdata.ReceivedFiles, filename)
				return nil, errors.New("HMAC has been altered, and so message has been corrupted!")
			}

			//decrypt, depad, and unmarshal the file struct
			marshFilestruct := userlib.SymDec(sharedR.Ekey, storedFilestruct.EncryptedM)
			marshFilestruct = dePad(marshFilestruct)

			var fileS File
			json.Unmarshal(marshFilestruct, &fileS)

			for i, fileUUID := range fileS.Files {
				fileBlock, _ := userlib.DatastoreGet(fileUUID)
				i = i

				var tempFile Stored
				//unmarshal and decrypt the File
				json.Unmarshal(fileBlock, &tempFile)

				//check HMAC
				fileHMAC, _ := userlib.HMACEval(sharedR.HmacKey, tempFile.EncryptedM)

				if !userlib.HMACEqual(tempFile.HMAC, fileHMAC ) {
					return nil, errors.New("HMAC has been altered, and so message has been corrupted")
				}

				//decrypt the file
				fileEncrypted := userlib.SymDec(sharedR.Ekey, tempFile.EncryptedM)
				decryptedFile := dePad(fileEncrypted)

				//append onto output byte
				//what does the ... mean? looks fine though
				output = append(output, decryptedFile...)
			}
			return output, nil
		} else {
			delete(userdata.ReceivedFiles, filename)
			return nil, errors.New("this file has been revoked for the user")
		}
	} else {
		return nil, errors.New("This file doesn't exist for the user")
	}
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.
//should HMAC with the recipient's password
//encrypted with proper encryption key
//IN DATASTORE
type SharingRecord struct {
	Ekey []byte
	Sender string
	Datalocation userlib.UUID
	Hmac []byte
	HmacKey []byte
}

//the arguments for this will make up the magic_string
//this will be stored in the users struct, pointing to sharing record which is on the datastore, which points to the filestruct
//IN USER STRUCT
type AccessRecord struct {
	Key []byte
	Recordlocation userlib.UUID
	RecordHMAC []byte
}

//helper function which computes if the sharing record has not been revoked / deleted
//Might be a problem in init, keystore values should universally be of type PublicKeyType but keystore DS and PK are diff types
func (userdata *User) stillShared(filename string) (shared bool) {
	//access record values to help find/decrypt sharing record if exists
	recordLocation := userdata.ReceivedFiles[filename].Recordlocation

	//err = false if the datastore has no value at recordLocation, meaning that the sharing record has been deleted
	//and the user no loner has access to the file
	_, err := userlib.DatastoreGet(recordLocation)
	if err == false {
		return false
	} else if err == true {
		return true
	}
	return false
}

type Signed struct {
	Sig []byte
	Message []byte
	Message2 []byte
}

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

//Only owner of the file can revoke, and he will can only revoke direct children! (other behavior = undefined)
//Return error if share fails or any malicious activity
func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	//initialize the "sender string" for sharing record
	sender := userdata.Username
	recipPublic, exists := userlib.KeystoreGet(recipient + "PK")
	if exists != true {
		return "", errors.New("recipient does not exist")
	}
	var recordUuid userlib.UUID
	stillShared := userdata.stillShared(filename)
	//encryption key for sharing record, to share to recipient through accesstruct
	var eKey []byte
	var User_HMAC []byte
	//if the user has stored the file themself:
	//pull the user's fileKeys for specific filename
	if fileKeys, ok := userdata.Files[filename]; ok {
		//pull the user's filestruct encryption key from file's fileKeys struct
		plainkey := fileKeys.EKey

		//get data location from fileKeys
		filelocation := fileKeys.FileStruct

		//get hmac from fileKeys
		hmacKey := fileKeys.HMACKey

		//create and populate the sharing record with its arguments
		var record SharingRecord
		record.Datalocation = filelocation
		record.Ekey = plainkey
		record.Sender = sender
		salt2 := userlib.Hash([]byte(filename + userdata.Password + userdata.Username))
		HashKey := userlib.Argon2Key([]byte(userdata.Password), salt2[:16], uint32(userlib.AESKeySize))
		record.HmacKey = HashKey
		record.Hmac = hmacKey

		//checks if file is tampered with before sharing
		var storedFileStruct Stored
		storedfileCheck, _ := userlib.DatastoreGet(filelocation)
		json.Unmarshal(storedfileCheck, storedFileStruct)
		HmacStored, _ := userlib.HMACEval(HashKey, storedFileStruct.EncryptedM)
		if userlib.HMACEqual(HmacStored, storedFileStruct.HMAC) {
			return "", errors.New("file has been tampered with")

		}

		//symmetrically encrypt sharingRecord with randomly generated key
		//first marshal then pad record struct
		marshRecord, _ := json.Marshal(record)
		marshRecord = padFile(marshRecord)
		//generate IV
		IV := userlib.RandomBytes(userlib.AESKeySize)
		//generate key for Symmetric encryption
		salt := userlib.Hash([]byte(userdata.Password + userdata.Username))
		encryptionKey := userlib.Argon2Key([]byte(userdata.Password), salt[:16], uint32(userlib.AESKeySize))
		//encrypt the user struct
		encryptedMessage := userlib.SymEnc(encryptionKey, IV, marshRecord)
		//Get the HMAC key
		hashKey := userlib.Argon2Key([]byte(userdata.Password), salt[16:], uint32(userlib.AESKeySize))
		User_HMAC, _ = userlib.HMACEval(hashKey, []byte(encryptedMessage))

		storedRecord := Stored{User_HMAC, encryptedMessage}
		marshStoredrecord, _ := json.Marshal(storedRecord)

		//store signed/marshalled/encrypted sharing record in the datastore at a random uuid
		recordUuid = uuid.New()
		userlib.DatastoreSet(recordUuid, marshStoredrecord)

		userdata.RecordKeys[filename + recipient] = encryptionKey

		eKey = encryptionKey

		//else if the user has received the file from someone else and user still has access to the file they received
	} else if senderAccess, ok := userdata.ReceivedFiles[filename]; ok && stillShared {
		//share the same sharing record sender uses with the recipient (when sender access gets revoked, so does recipient's)
		recordUuid = senderAccess.Recordlocation
		eKey = senderAccess.Key
		User_HMAC = senderAccess.RecordHMAC
		//if sender doesn't have access to the file, this should be untested behavior
	} else if ok {
		//delete the accessStruct for sender's file because senders access to the file is gone, no point in having an access struct for it
		delete(userdata.ReceivedFiles, filename)
		stillShared = false
		return "", errors.New("the sender no longer has the file in question")
	} else {
		return "", errors.New("the sender does not have the file in question")
	}

	//set pointer to the new sharing record in the user's userdata
	userdata.SharedFiles[filename + recipient] = recordUuid

	//create accessRecord with necessary info to point to sharingRecord, properly encrypt/format as a magic_string, then return this magic_string
	var access AccessRecord
	access.Key = eKey
	access.Recordlocation = recordUuid
	access.RecordHMAC = User_HMAC
	marshAccess, _ := json.Marshal(access)

	cipherAccess, _ := userlib.PKEEnc(recipPublic, marshAccess[:len(marshAccess)/2])
	cipherAccess2, _ := userlib.PKEEnc(recipPublic, marshAccess[len(marshAccess)/2:])


	accessSig, _ := userlib.DSSign(userdata.DS, marshAccess)
	signedAccess := Signed{accessSig, cipherAccess, cipherAccess2}

	marshSignedaccess, _ := json.Marshal(signedAccess)

	magic_string = hex.EncodeToString(marshSignedaccess)

	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.

// may have to reencrypt user data and restore onto datastore since we added something to one of its maps, this means
// that we may have to do the same when calling storefile
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

	if _, ok := userdata.Files[filename]; ok {
		return errors.New("User already has the file")
	} else if _, ok2 := userdata.ReceivedFiles[filename]; ok2 {
		if userdata.stillShared(filename) {
			return errors.New("User has already received the file, and still has access to it")
		} else {
			//file has been revoked from this user before, delete revoked/invalid access record
			delete(userdata.ReceivedFiles, filename)
		}
	}

	//decode magic_string into an array of marshalled bytes, unmarshal this into the signed struct
	magicBytes, _ := hex.DecodeString(magic_string)

	var signedAccess Signed
	json.Unmarshal(magicBytes, &signedAccess)

	//decode encrypted/marshalled accessStruct
	marshAccess, _ := userlib.PKEDec(userdata.RSA, signedAccess.Message)
	marshAccess2, _ := userlib.PKEDec(userdata.RSA, signedAccess.Message2)

	marshAccess = append(marshAccess, marshAccess2...)

	//Verify signature
	senderPub, _ := userlib.KeystoreGet(sender + "DS")

	err := userlib.DSVerify(senderPub, marshAccess, signedAccess.Sig)
	if err != nil {
		return errors.New("Access Token has been modified, digital signature system failed to verify expected sender")
	}

	var access AccessRecord
	_ = json.Unmarshal(marshAccess, &access)

	//store accessRecord struct in userdata
	if userdata.ReceivedFiles == nil {
		userdata.ReceivedFiles = make(map[string]AccessRecord)
	}
	userdata.ReceivedFiles[filename] = access

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	if _, ok := userdata.Files[filename]; !ok {
		return errors.New("this user does not have the file he is trying to revoke")
	}

	//pointer to the encrypted struct in the datastore that gives the target access to the file (via encryption key, and datastore location)
	recordUuid := userdata.SharedFiles[filename + target_username]

	//In the datastore, delete this access struct pointed to bt above uuid; and so the target will not have access to the keys/location of the filedata
	userlib.DatastoreDelete(recordUuid)

	return nil
}
