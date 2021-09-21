package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

//this is going to test init
func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.

	//test if you try to store a repeat username
	_, err2 := InitUser("alice", "jclaei")
	if err2 == nil {
		t.Error("Failed to check if username already exists")
		return
	}

	//check if I entered the wrong password
	_, err3 := GetUser("alice", "fugazibar")
	if err3 == nil {
		t.Error("Did not error for the wrong password entered")
	}
}

func TestStorage(t *testing.T) {
	clear()
	bilalPointer, err := InitUser("Bilal", "Syed")
	if err != nil {
		t.Error("Basic init did not work", err)
		return
	}

	data := []byte("Bilal likes bananas")
	bilalPointer.StoreFile("file1", data)

	dataCopy, err2 := bilalPointer.LoadFile("file1")
	if err2 != nil {
		t.Error("System failed to load stored file", err2)
		return
	}
	if !reflect.DeepEqual(data, dataCopy) {
		t.Error("Loaded file is not the same as the one we stored", data, dataCopy)
		return
	}
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestRevoke(t *testing.T) {
	clear()
	var data []byte
	var magic_string string

	bilalPointer, err := InitUser("Bilal", "Syed")
	if err != nil {
		t.Error("Failed to initialize Bilal", err)
		return
	}
	saadPointer, err2 := InitUser("Saad", "Sayed")
	if err2 != nil {
		t.Error("Failed to initialize Saad", err2)
		return
	}
	ahsanPointer, err3 := InitUser("Ahsan", "Seeyed")
	if err3 != nil {
		t.Error("Failed to initialize Ahsan", err2)
		return
	}

	// Bilal is Owner of 'bilalstored'
	fileData := []byte("This is a test")
	bilalPointer.StoreFile("bilalFile", fileData)

	// Share with Saad
	magic_string, err = bilalPointer.ShareFile("bilalFile", "Saad")
	if err != nil {
		t.Error("Failed to share bilalFile to Saad ", err)
		return
	}
	err = saadPointer.ReceiveFile("saadReceived", "Bilal", magic_string)
	if err != nil {
		t.Error("Saad failed to receive the file from Bilal", err)
		return
	}
	//fmt.Println("File shared successfully from Bilal to Saad")

	// Saad shares file saadReceived with Ahsan
	magic_string, err = saadPointer.ShareFile("saadReceived", "Ahsan")
	if err != nil {
		t.Error("Failed to share received file from Saad to Ahsan", err)
		return
	}
	err = ahsanPointer.ReceiveFile("ahsanReceived", "Saad", magic_string)
	if err != nil {
		t.Error("Ahsan failed to receive the file from Saad", err)
		return
	}
	//fmt.Println("File shared successfully from Saad to Ahsan")

	//check if each of the people w access to the file can append to it
	appOne := []byte(" for")
	err = bilalPointer.AppendFile("bilalFile", appOne)
	if err != nil {
		t.Error("Owner Bilal appending to file did not work", err)
		return
	}

	appTwo := []byte(" my")
	err = saadPointer.AppendFile("saadReceived", appTwo)
	if err != nil {
		t.Error("Direct sharee Saad appending to file did not work", err)
		return
	}

	appThree := []byte(" safety")
	err = ahsanPointer.AppendFile("ahsanReceived", appThree)
	if err != nil {
		t.Error("Sub sharee Ahsan appending to file did not work", err)
		return
	}
	//check if the file data is equal for all three of people w access to the file
	bilalsData, errLoadone := bilalPointer.LoadFile("bilalFile")
	if errLoadone != nil {
		t.Error("Saad's file didn't load as expected", errLoadone)
	}

	saadsData, errLoadtwo := saadPointer.LoadFile("saadReceived")
	if errLoadtwo != nil {
		t.Error("Saad's file didn't load as expected", errLoadtwo)
	}

	ahsansData, errLoadthree := ahsanPointer.LoadFile("ahsanReceived")
	if errLoadthree != nil {
		t.Error("Saad's file didn't load as expected", errLoadthree)
	}

	if !reflect.DeepEqual(bilalsData, saadsData)  || !reflect.DeepEqual(ahsansData, saadsData) || !reflect.DeepEqual(bilalsData, ahsansData){
		t.Error("the file data for all three are not the same, meaning append didn't work for all three of people with access", bilalsData, saadsData, ahsansData)
		return
	}

	expected := []byte("This is a test for my safety")
	if !reflect.DeepEqual(expected, bilalsData) {
		t.Error("the file data after three appends is not as expected", expected, bilalsData)
		return
	}

	//THIS CASE WILL NOT BE TESTED, UNDEFINED BEHAVIOR
	//Saad tries to revoke ahsan's access to the file, which he shouldn't be able to do
	//err = saadPointer.RevokeFile("saadReceived", "Ahsan")
	//if err == nil {
	//	t.Error("Saad should not be allowed to revoke Ahsan's access, since Saad is not the owner", err)
	//	return
	//}
	//check if share to nonexistent recipient works
	_, shareValid := bilalPointer.ShareFile("bilalFile", "nonexistentuser")
	if shareValid == nil {
		t.Error("shared file to a nonexistent user, error!", shareValid)
		return
	}

	//Bilal revokes Saad's access to file, which should revoke both Saad and Ahsan's access to the file
	err = bilalPointer.RevokeFile("bilalFile", "Saad")
	if err != nil {
		t.Error("Failed to revoke Saad's access to the file", err)
		return
	}
	data, err = saadPointer.LoadFile("saadReceived")
	if data != nil {
		t.Error("Despite calling revoke, Saad still has access, error!", err)
		return
	}
	data, err = ahsanPointer.LoadFile("ahsanReceived")
	if data != nil {
		t.Error("Saad's child Ahsan still has access to the file despite Saad's access being revoked, error!", err)
		return
	}
	//fmt.Println("File has successfully been revoked from Saad and Ahsan")

	//let's see if Saad and Ahsan can still append to the file that has been revoked for them
	var toAppend []byte = []byte("SHEEEEEEESH")
	errsheesh := saadPointer.AppendFile("saadReceived", toAppend)
	if errsheesh == nil {
		t.Error("Saad was still able to append to a file that he should no longer have access to, error!", errsheesh)
		return
	}
	errsheesh2 := ahsanPointer.AppendFile("ahsanReceived", toAppend)
	if errsheesh2 == nil {
		t.Error("Ahsan was still able to append to a file that he should no longer have access to, error!", errsheesh2)
		return
	}

	//share to Saad again, see if Saad can load the file
	newmagic, againShare := bilalPointer.ShareFile("bilalFile", "Saad")
	if againShare != nil {
		t.Error("Failed to share a file with Saad" ,againShare)
		return
	}
	reupFail := saadPointer.ReceiveFile("saadReceived", "Bilal", newmagic)
	if reupFail != nil {
		t.Error("Failed to received a file from Bilal that was previously revoked for Saad", reupFail)
		return
	}
	data, err = saadPointer.LoadFile("saadReceived")
	if data == nil {
		t.Error("Saad failed to load a file that he should now have access to again", err)
		return
	}

	//bilal now appends data to the file, saad should be able to see appended data, but ahsan shouldn't!
	toAppend = []byte("on GOD")
	err4 := bilalPointer.AppendFile("bilalFile", toAppend)
	if err4 != nil {
		t.Error("bilal couldn't append data to file bilalFile", err4)
		return
	}
	bilalSees, err5 := bilalPointer.LoadFile("bilalFile")
	if err5 != nil {
		t.Error("bilal couldn't load file", err5)
		return
	}
	saadSees, err6 := saadPointer.LoadFile("saadReceived")
	if err6 != nil {
		t.Error("Saad could not load file", err6)
		return
	}
	if !reflect.DeepEqual(bilalSees, saadSees) {
		t.Error("After appending to bilalFile, the file that bilal sees becomes different than the one Saad sees", bilalSees, saadSees)
		return
	}
	_, shouldErr := ahsanPointer.LoadFile("ahsanReceived")
	if shouldErr == nil {
		t.Error("Ahsan shouldn't be able to load this file anymore since he doesn't have access!", shouldErr)
		return
	}
}

func TestOverwrite(t *testing.T) {
	clear()
	//create link and zelda users
	link, err := InitUser("link", "hyrule")
	if err != nil {
		t.Error("Failed to initialize user link", err)
		return
	}
	zelda, err := InitUser("zelda", "ganon")
	if err != nil {
		t.Error("Failed to initialize user zelda", err)
		return
	}
	ganondorf, err7 := InitUser("ganondorf", "moneyfamepowersuccess")
	if err7 != nil {
		t.Error("Failed to initialize user ganondorf", err)
		return
	}
	//store link file 'scrolls' and send to Zelda and Ganondorf
	scrolls := []byte("secret message to my girl zelda")
	link.StoreFile("scrolls", scrolls)
	magic, err2 := link.ShareFile("scrolls", "zelda")
	if err2 != nil {
		t.Error("link to zelda share failed", err2)
		return
	}
	err = zelda.ReceiveFile("fromLink", "link", magic)
	if err != nil {
		t.Error("zelda failed to receive file from link", err)
		return
	}
	magicg, err8 := link.ShareFile("scrolls", "ganondorf")
	if err8 != nil {
		t.Error("link to ganondorf share failed", err8)
		return
	}
	err = ganondorf.ReceiveFile("scrolls", "link", magicg)
	if err != nil {
		t.Error("ganondorf failed to receive file from link", err)
		return
	}
	//check if link overwriting 'scrolls' works as expected
	linkOverwrite := []byte("sike, that's the wrong number")
	link.StoreFile("scrolls", linkOverwrite)
	//og := []byte("secret message to my girl zelda")
	newnew, err3 := link.LoadFile("scrolls")
	if err3 != nil {
		t.Error("link failed to load his file called scrolls", err3)
		return
	}
	if !reflect.DeepEqual(linkOverwrite, newnew) {
		t.Error("link failed to overwrite the old file scrolls with the new stored data", linkOverwrite, newnew)
		return
	}
	//check if zelda's file data is the same as link's overwritten version (should be)
	zeldanew, err4 := zelda.LoadFile("fromLink")
	if err4 != nil {
		t.Error("zelda failed to load her file called fromLink", err4)
		return
	}
	if !reflect.DeepEqual(newnew, zeldanew) {
		t.Error("zelda's file data is not the same as links for the same file, error!", newnew, zeldanew)
		return
	}
	//check if ganondorf's file data is the same as link's overwritten version
	ganonnew, err9 := ganondorf.LoadFile("scrolls")
	if err9 != nil {
		t.Error("ganon failed to load his file called scrolls", err4)
		return
	}
	if !reflect.DeepEqual(newnew, ganonnew) {
		t.Error("ganons's file data is not the same as links for the same file, error!", newnew, ganonnew)
		return
	}
	//zelda overwrites file, check if the load of overwritten file is as expected
	zeldaOverwrite := []byte("soulja jus beat supa hot")
	zelda.StoreFile("fromLink", zeldaOverwrite)
	zeldaloadsover, err5 := zelda.LoadFile("fromLink")
	if err5 != nil {
		t.Error("zelda's failed to load the file at fromlink", err5)
		return
	}
	if !reflect.DeepEqual(zeldaOverwrite, zeldaloadsover) {
		t.Error("zelda failed to overwrite the old file fromLink with the new stored data", zeldaOverwrite, zeldaloadsover)
		return
	}
	//check if zelda's overwrite held for links file as well
	linkCheck, err6 := link.LoadFile("scrolls")
	if err6 != nil {
		t.Error("link failed to load the file scrolls", err6)
		return
	}
	if !reflect.DeepEqual(linkCheck, zeldaloadsover) {
		//fmt.Println(string(finalCheck))
		t.Error("zelda's overwrite of fromLink did not overwrite link's file scrolls, which was supposed to happen", linkCheck, zeldaloadsover)
		return
	}
	//check if zelda's overwrite held for ganondorf's file as well
	ganonCheck, err10 := link.LoadFile("scrolls")
	if err10 != nil {
		t.Error("ganon failed to load the file scrolls", err10)
		return
	}
	if !reflect.DeepEqual(ganonCheck, zeldaloadsover) {
		//fmt.Println(string(finalCheck))
		t.Error("zelda's overwrite of fromLink did not overwrite ganon's file scrolls, which was supposed to happen", ganonCheck, zeldaloadsover)
		return
	}
}
func TestRepeat(t *testing.T) {
	clear()
	var magic_string string

	avocado, err := InitUser("avocado", "fire")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	pineApple, err2 := InitUser("pineApple", "hans")
	if err2 != nil {
		t.Error("Failed to initialize pineApple", err2)
		return
	}
	// avocado is the owner of fruitfile, and pineApple is also the owner of a different fruitfile
	test := []byte("test")
	avocado.StoreFile("fruitfile", test)
	// B is also an owner of a file called fruitfile
	testTwo := []byte("anotha one")
	pineApple.StoreFile("fruitfile", testTwo)

	// avocado tries to share fruitfile with pineapple, should fail
	magic_string, err = avocado.ShareFile("fruitfile", "pineApple")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = pineApple.ReceiveFile("fruitfile", "avocado", magic_string)
	if err == nil {
		t.Error("pineApple should not be able to receive fruitfile since he already has one", err)
		return
	}

	// Try to share avocado's fruitfile under a different name! this should work
	magic_string, err = avocado.ShareFile("fruitfile", "pineApple")
	if err != nil {
		t.Error("Failed to share fruitfile to pineApple", err)
		return
	}
	err = pineApple.ReceiveFile("avofile", "avocado", magic_string)
	if err != nil {
		t.Error("pineApple failed to receive avocado's fruitfile under the alias avofile", err)
		return
	}

	// Try to share fruitfile as avofile again, which should fail bc pineapple already has it now
	magic_string, err = avocado.ShareFile("fruitfile", "pineApple")
	if err != nil {
		t.Error("Failed to share fruitfile with pineApple", err)
		return
	}
	err = pineApple.ReceiveFile("avofile", "avocado", magic_string)
	if err == nil {
		t.Error("Avocado should not be able to share fruitfile as avofile a second time, error", err)
		return
	}
}

//test wrong sender in call to receive -> error bc can't decrypt magic string
func TestSender(t *testing.T) {
	//initialize aang and toph users
	aang, err := InitUser("Aang", "appa")
	if err != nil {
		t.Error("could not initialize user Aang", err)
		return
	}
	toph, err2 := InitUser("Toph", "metal")
	if err2 != nil {
		t.Error("could not initialize user Toph", err2)
		return
	}
	bendingScroll := []byte("this is how to air bend")
	aang.StoreFile("Air", bendingScroll)
	magic, err3 := aang.ShareFile("Air", "Toph")
	if err3 != nil {
		t.Error("could not share file Air to Toph", err3)
		return
	}
	//receive file from Aang but with wrong sender name!
	shouldErr := toph.ReceiveFile("Air", "CabbageMan", magic)
	if shouldErr == nil {
		t.Error("Toph shouldn't be able to receive the file from CabbageMan, someone who hasn't been initialized, nor would know how to bend", shouldErr)
		return
	}
	//initialize katara user, _ because we won't actually use katara's user data
	_, err4 := InitUser("Katara", "southern")
	if err4 != nil {
		t.Error("could not initialize user Katara", err4)
		return
	}
	//test if toph receives file from Katara, while she is an initialized user, she is not the right sender
	shouldErr = toph.ReceiveFile("Air", "Katara", magic)
	if shouldErr == nil {
		t.Error("Toph should not be able to receive this file from Katara since she wasn't the proper sender", shouldErr)
		return
	}
	//properly share with Toph
	err5 := toph.ReceiveFile("Air", "Aang", magic)
	if err5 != nil {
		t.Error("Toph could not receive the file from aang, error!", err5)
		return
	}
}

func TestMagic(t *testing.T) {
	jordan, err := InitUser("Jordan", "Chicago")
	if err != nil {
		t.Error("could not initialize Jordan", err)
		return
	}
	kobe, err2 := InitUser("Kobe", "dedication")
	if err2 != nil {
		t.Error("could not initialize Kobe", err2)
		return
	}
	//jordan is going to store a file, and then try to share it with kobe, the secret to how to properly fade away
	secret := []byte("the key to fade away success manual")
	jordan.StoreFile("theTorch", secret)
	magic, err3 := jordan.ShareFile("theTorch", "Kobe")
	if err3 != nil {
		t.Error("Jordan could not share file theTorch to Kobe", err3)
		return
	}
	//however, adversary paul pierce tries to change the input to receiveFile
	truth := "the truth"
	//now kobe tries to receive the secret to success
	shouldErr := kobe.ReceiveFile("theTorch", "Jordan", truth)
	if shouldErr == nil {
		t.Error("the corrupted magic string went unnoticed by receiveFile, error!", shouldErr)
		return
	}
	//now Kobe tries to receive proper file
	err4 := kobe.ReceiveFile("theTorch", "Jordan", magic)
	if err4 != nil {
		t.Error("Kobe could not receive theTorch file from Jordan", err4)
		return
	}
	//now kobe tries to receive the file again, but he already has it -> should error
	shouldErr = kobe.ReceiveFile("theTorch", "Jordan", magic)
	if shouldErr == nil {
		t.Error("Kobe already has the file he's trying to receive, error!", shouldErr)
		return
	}
	//create Carmelo Anthony user struct, he will try to get the file from Jordan as well, but the magic was encrypted specifically for Kobe
	melo, err5 := InitUser("Carmelo", "slim")
	if err5 != nil {
		t.Error("Could not initialize Carmelo", err5)
		return
	}
	shouldErr = melo.ReceiveFile("theTorch", "Jordan", magic)
	if shouldErr == nil {
		t.Error("Carmelo should not be able to receive theTorch file, the magic string was not encrypted for him, and he isn't the chosen one", shouldErr)
		return
	}
}

func TestHasfile(t *testing.T) {
	//create joker and batman
	joker, err := InitUser("Joker", "how I got these scars")
	if err != nil {
		t.Error("Failed to initialize clown user", err)
		return
	}
	//_ because won't actually use batman userdata
	_, err2 := InitUser("Batman", "Bruce Wayne")
	if err2 != nil {
		t.Error("Could not initialize Batman", err2)
		return
	}
	nonAppend := []byte("somne people just want to watch the world burn")
	shouldErr := joker.AppendFile("BruceBirthCertif", nonAppend)
	if shouldErr == nil {
		t.Error("Joker shouldn't be able to append to a file he does not have", shouldErr)
		return
	}
	shouldErr = joker.RevokeFile("Power", "Batman")
	if shouldErr == nil {
		t.Error("Joker could not get rid of Batman's power, because he has no Power himself", shouldErr)
		return
	}
	_, shouldErr = joker.ShareFile("Mask", "Batman")
	if shouldErr == nil {
		t.Error("Joker cannot share a Mask he does not have to Batman; Joker doesn't wear a mask", shouldErr)
		return
	}
	_, shouldErr = joker.LoadFile("Restraints")
	if shouldErr == nil {
		t.Error("Joker has no restraints, and so he cannot load them", shouldErr)
		return
	}
}

func TestTamperFile (t *testing.T) {
	LBJ, err := InitUser("Lebron James", "goatman")
	if err != nil {
		t.Error("Failed to initialize goat user", err)
		return
	}
	secret := []byte("the key to fade away success manual")
	LBJ.StoreFile("theTorch", secret)

	DataMap := userlib.DatastoreGetMap()
	t.Log(DataMap)
	tamper := []byte("Kd is the goat")
	for key := range DataMap {
		userlib.DatastoreSet(key, tamper)
	}
	Lebron, err := GetUser("Lebron James", "goatman")
	Lebron = Lebron
	if err == nil {
		t.Error("Error", err)
		return
	}
}

//test if invalid file or not
/*func TestFilevalid(t *testing.T) {
	jon, err := InitUser("jon", "snow")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	tyrion, err2 := InitUser("tyrion", "imp")
	if err2 != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	secret := []byte("i am a targaryen")
	jon.StoreFile("secret", secret)

	magic_string, err := jon.ShareFile("secret", "tyrion")

}

 */





