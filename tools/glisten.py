#!/usr/bin/env python3

"""garak listener

Service that listens on test ports, stores activity, and returns summary results.
The listener has a service port that processes instructions and relays results.
Only one set of results is stored at a time.

Results are intentionally ephemeral.

Invocation from garak source root:

  python tools/glisten.py

Service protocol instructions:
 
 INFO

  * return as JSON ``{"status": {"code":0, "message":"OK"}, "version":"glisten v.xxxxx"}``

 START <id str> <port spec>

  * discard all current results
  * try to bind to ports in port spec (comma separated list) (max #MAX_PORTS_LISTENED ports)
  * listen for connection attempts and content on these ports
  * return dict as JSON,  ``{"status": {"code":1, "message":"garak listen started"}``

 COLLECT <id str>
  
  * if <id str> does not match the current run or there is no current run, return
    in JSON ``{"status": {"code": 2, "message": "no run under that ID"}}``
  * if <id str> does match the current run,
    
    * return a dict with:

      * "status" of code 3, message "ending run" 
      * "results" which is a list, each entry being:

        * "port" with port number
        * "bound" with True of False, relaying whether binding worked
        * if bound is True:

            * "opened" which is True or False
            * "content" which is a list of first ``MAX_CONTENT_LOGGED`` bytes of content sent

  * discard all current results ``{"status": {"code":3, "message":"unrecognised command"}``

 Other and invalid inputs return {} 

Note that START can always be used to "flush" the service, even with the same ID.

Recommend a slight delay/backoff after a first failed COLLECT attempt, to mitigate ID brute forcing.

A local log can collect info on whether the server could bind ports, and on service instructions received
"""

import json
import logging
import selectors
import socket
import time
import types

SERVICE_PORT = 9218
HOST = "127.0.0.1"
MAX_CONTENT_LOGGED = 131072  # bytes
MAX_PORTS_LISTENED = 250
MAX_LISTENERS_PER_PORT = 32  # this might like to be in the region of parallel_attempts


class GListener:

    def __init__(self, config=dict()) -> types.NoneType:
        self.service_port = SERVICE_PORT
        self.sel = selectors.DefaultSelector()
        self._reset_session()

    def _accept_wrapper(self, sock):
        conn, addr = sock.accept()
        local_addr, local_port = conn.getsockname()
        info_msg = f"accepted conxn from {addr} on port {local_port}"
        logging.info(info_msg)
        print(addr, f"connected to {local_port}")
        conn.setblocking(False)
        data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
        events = selectors.EVENT_READ | selectors.EVENT_WRITE
        self.sel.register(conn, events, data=data)

    def _send_as_json(self, obj, sock):
        obj_str = json.dumps(obj)
        sent = sock.send(bytes(obj_str + "\n", encoding="utf-8"))
        return sent

    def _send_err(self, sock, explanation: str = ""):
        msg_obj = {"status": {"code": 3, "message": "unrecognised command"}}
        if explanation:
            msg_obj["status"]["message"] += f": {explanation}"
        sent = self._send_as_json(msg_obj, sock)
        return sent

    def _start(self, id, portspec):
        self._reset_session()
        self.session_id = id
        self.status["session_id"] = self.session_id
        msg_obj = {"status": {"code": 1, "message": "garak listen started"}}
        test_ports = self._expand_port_spec(portspec)
        if len(test_ports) > MAX_PORTS_LISTENED:
            note = f"{len(test_ports)} ports requested, reducing request to {MAX_PORTS_LISTENED}"
            logging.warning(note)
            msg_obj["note"] = note
            test_ports = list(test_ports)[:250]
        for test_port in test_ports:
            self._open_port(int(test_port))
        return msg_obj

    def _expand_port_spec(self, port_spec: str):
        ports = set()
        for entry in port_spec.split(","):
            if "-" not in entry:
                try:
                    ports.add(str(entry))
                except ValueError:
                    continue
            else:
                start_s, end_s = entry.split("-")
                try:
                    start_port, end_port = int(start_s), int(end_s)
                except ValueError:
                    continue
                range_items = range(start_port, end_port + 1)
                ports = ports.union(range_items)
        return ports

    def _collect(self, id):
        if id == self.session_id:
            collected_status = self.status
            self._reset_session()
            return collected_status
        else:
            msg_obj = {"status": {"code": 2, "message": "no run under that ID"}}
            if self.delay:
                time.sleep(0.15)  # praying this blocks thread not service
            return msg_obj

    def _serve_service_connection(self, key, mask):
        data = key.data
        sock = key.fileobj
        instruction = b""
        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(1024)
            if recv_data:
                instruction = recv_data
            else:
                logging.info(f"closing conxn to {data.addr}")
                self.sel.unregister(sock)
                sock.close()
        if mask & selectors.EVENT_WRITE:
            instruction_parts = instruction.strip()
            if not instruction_parts:
                return
            try:
                instruction_parts = instruction_parts.decode("utf-8").split()
            except UnicodeDecodeError:
                self._send_err(sock, explanation="Unicode decoding error")
                return
            logging.info(f"{data.addr}: {instruction_parts[:100]}")
            print(data.addr, instruction_parts)
            if instruction_parts[0] == "INFO":
                msg_obj = {
                    "status": {"code": 0, "message": "OK"},
                    "version": "glisten v.0.0.0",
                }
                sent = self._send_as_json(msg_obj, sock)
            elif instruction_parts[0] == "START":
                if len(instruction_parts) != 3:
                    self._send_err(sock, explanation="START takes two args")
                else:
                    msg_obj = self._start(instruction_parts[1], instruction_parts[2])
                    self._send_as_json(msg_obj, sock)

            elif instruction_parts[0] == "COLLECT":
                if len(instruction_parts) != 2:
                    self._send_err(sock, "COLLECT takes one arg")
                else:
                    msg_obj = self._collect(instruction_parts[1])
                    self._send_as_json(msg_obj, sock)
            else:
                self._send_err(sock)

    def _serve_test_connection(self, key, mask):
        data = key.data
        sock = key.fileobj
        _, port = sock.getsockname()
        self.status[port]["opened"] = True

        if mask & selectors.EVENT_READ:
            recv_data = sock.recv(MAX_CONTENT_LOGGED)
            if recv_data:
                data.outb += recv_data
            else:
                logging.info(f"closing conxn to {data.addr}")
                self.sel.unregister(sock)
                sock.close()
        if mask & selectors.EVENT_WRITE:
            content_str = data.outb.decode("utf-8")[:MAX_CONTENT_LOGGED]
            self.status[port]["content"] = content_str

    def _serve_connection(self, key, mask):
        if key.fileobj.fileno() > 0:  # closing/closed FDs don't have this info
            local_host, local_port = key.fileobj.getsockname()
            if local_port == self.service_port:
                self._serve_service_connection(key, mask)
            else:
                self._serve_test_connection(key, mask)

    def _reset_session(self):
        self.delay = False
        self.session_id = None
        self.status = {}
        # close non-service selectors
        for i in list(self.sel.get_map().keys()):
            sock = self.sel.get_key(i).fileobj
            laddr_host, laddr_port = sock.getsockname()
            if laddr_port != self.service_port:
                self.sel.unregister(sock)
                sock.close()

    def _open_port(self, port):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((HOST, port))
            logging.info(f"bound to {HOST}:{port}")
            if port != self.service_port:
                self.status[port] = {"bound": True, "opened": False}
        except:
            if port != self.service_port:
                self.status[port] = {"bound": False}
            return False
        sock.listen()
        logging.info(f"listening")
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, data=None)
        return True

    def _init_service(self):

        r = self._open_port(self.service_port)
        if r == False:
            logging.critical("couldn't bind to service port")

        try:
            while True:
                events = self.sel.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        self._accept_wrapper(key.fileobj)
                    else:
                        self._serve_connection(key, mask)
        except KeyboardInterrupt:
            logging.info("Caught keyboard interrupt, exiting")
        finally:
            self.sel.close()

    def start(
        self,
    ):
        logging.info("starting")
        self._init_service()


if __name__ == "__main__":
    glisten = GListener()
    glisten.start()
