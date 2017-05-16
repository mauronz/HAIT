# Visualization components
# Derived from Villoc https://github.com/wapiflapi/villoc
  
import cgi
import random
import codecs



class State(list):

    def __init__(self, *args, **kwargs):
        self.errors = []
        self.info = []
        super(State, self).__init__(*args, **kwargs)

    def boundaries(self):
        bounds = set()
        for block in self:
            lo, hi = block.boundaries()
            bounds.add(lo)
            bounds.add(hi)
        return bounds


class Printable(object):

    unit_width = 12
    classes = ["block"]

    def boundaries(self):
        return (self.start(), self.end())

    def gen_html(self, out, width, color="", id_block=""):
        out.write('<div class="%s" %s style="width: %dem; %s;">' %
                  (" ".join(self.classes), id_block, Printable.unit_width * width, color))
        if self.details:
            out.write('<strong>%#x</strong><br />' % self.start())
            out.write(self.more_html())
        else:
            out.write('&nbsp;')

        out.write('</div>\n')

    def more_html(self):
        return ""

    def __repr__(self):
        return "%s(start=%#x, end=%#x)" % (self.__class__.__name__,
                                           self.start(), self.end())


class Empty(Printable):

    classes = Printable.classes + ["empty"]

    id_count = 1

    def __init__(self, start, end, display=True):
        self._start = start
        self._end = end
        self.details = display
	self.raddr = start
	self.rsize = end - start
	self.id = Empty.id_count	
	Empty.id_count += 1
	self.prev_inuse = 0
	self.is_mmapped = 0
	self.non_main_arena = 0
	self.fd = 0
	self.bk = 0

    def new_id(self) :
	self.id = Empty.id_count
	Empty.id_count += 1

    def set_flags(self, byte) :
	self.prev_inuse = byte & 0b1

	self.is_mmapped = (byte & 0b10) >> 1

	self.non_main_arena =  (byte & 0b100) >> 2

    def set_links(self, fd, bk) :
	self.fd = fd
	self.bk = bk

    def to_json(self) :
	return '{fd: 0x%x, bk: 0x%x, ' \
		'raddr: 0x%x, rsize: 0x%x, ' \
		'prev_inuse: %d, is_mmapped: %d, non_main_arena: %d}' \
		% (self.fd, self.bk, 
		self.start(), self.end() - self.start(), 
		self.prev_inuse, self.is_mmapped, self.non_main_arena)

    def start(self):
        return self.raddr

    def end(self):
        return self._end

    def set_end(self, end):
        self._end = end

    def gen_html(self, out, width) :
	id_string = 'id="empty%d"' % (self.id)
        super(Empty, self).gen_html(out, width, "", id_block=id_string)

    def more_html(self):
        return "+ %#x" % (self.end() - self.start())


class Block(Printable):

    header = 8 
    footer = 0
    round = 0x10
    minsz = 0x20

    id_count = 1

    classes = Printable.classes + ["normal"]

    def __init__(self, addr, size, error=False, tmp=False, controlled=False, **kwargs):
        self.color = kwargs.get('color', random_color())
        self.uaddr = addr
	self.raddr = self.uaddr - self.header
        self.usize = size
	self.rsize = self.end() - self.raddr
        self.details = True
        self.error = error
        self.tmp = tmp
	self.controlled = controlled
	self.id = Block.id_count	
	Block.id_count += 1
	self.prev_inuse = 0
	self.is_mmapped = 0
	self.non_main_arena = 0

    def new_id(self) :
	self.id = Block.id_count
	Block.id_count += 1

    def set_flags(self, byte) :
	self.prev_inuse = byte & 0b1

	self.is_mmapped = (byte & 0b10) >> 1

	self.non_main_arena =  (byte & 0b100) >> 2

    def to_json(self) :
	return '{uaddr: 0x%x, usize: 0x%x, ' \
		'raddr: 0x%x, rsize: 0x%x, ' \
		'prev_inuse: %d, is_mmapped: %d, non_main_arena: %d}' \
		% (self.uaddr, self.usize, 
		self.start(), self.end() - self.start(), 
		self.prev_inuse, self.is_mmapped, self.non_main_arena)


    def start(self):
        return self.uaddr - self.header

    def end(self):
        size = max(self.minsz, self.usize + self.header + self.footer)
        rsize = size + (self.round - 1)
        rsize = rsize - (rsize % self.round)
        return self.uaddr - self.header + rsize

    def gen_html(self, out, width):

        if self.color:
            color = ("background-color: rgb(%d, %d, %d);" % self.color)
	    
	    if self.controlled:
	       color += "-webkit-border-radius: 0.25em; -moz-border-radius: 0.25em; border-radius: 0.25em; border:#FFA500 solid 0.4em;"
        else:
            color = ""

        if self.error:
            color += ("background-image: repeating-linear-gradient("
                      "120deg, transparent, transparent 1.40em, "
                      "#A85860 1.40em, #A85860 2.80em);")

	id_string = 'id="block%d"' % (self.id)
        super(Block, self).gen_html(out, width, color, id_block=id_string)

    def more_html(self):
        return "+ %#x (%#x)" % (self.end() - self.start(), self.usize)

    def __repr__(self):
        return "%s(start=%#x, end=%#x, tmp=%s)" % (
            self.__class__.__name__, self.start(), self.end(), self.tmp)


class Marker(Block):

    def __init__(self, addr, error=False, **kwargs):
        super(Marker, self).__init__(addr, 0x0, tmp=True, error=error, *kwargs)

    def more_html(self):
        return "unknown"

def random_color(r=255, g=255, b=51):

    red = (random.randrange(0, 256) + r) / 2
    green = (random.randrange(0, 256) + g) / 2
    blue = (random.randrange(0, 256) + b) / 2

    return (red, green, blue)

def print_state(out, boundaries, state):

    out.write('<div class="state %s">\n' % ("error" if state.errors else ""))

    known_stops = set()

    todo = state
    while todo:

        out.write('<div class="line" style="">\n')

        done = []

        current = None
        last = 0

        for i, b in enumerate(boundaries):

            # If this block has size 0; make it continue until the
            # next boundary anyway. The size will be displayed as
            # 0 or unknown anyway and it shouldn't be too confusing.
            if current and current.end() != b and current.start() != current.end():
                continue

            if current:  # stops here.		
                known_stops.add(i)
                current.gen_html(out, i - last)
                done.append(current)
                last = i

            current = None
            for block in todo:
                if block.start() == b:
                    current = block
                    break
            else:
                continue

            #if last != i:
		#print('last %d i %d' % (last, i))

                # We want to show from previous known_stop.

                #for s in reversed(range(last, i+1)):
                 #   if s in known_stops:
                  #      break

                #if s != last:
                #    Empty(boundaries[last], boundaries[s],
                #          display=False).gen_html(out, s - last)
                #    known_stops.add(s)

                #if s != i:
                #    Empty(boundaries[s], b).gen_html(out, i - s)
                #    known_stops.add(i)

                #last = i


        if current:
            raise RuntimeError("Block was started but never finished.")

        if not done:
            raise RuntimeError("Some block(s) don't match boundaries.")

        out.write('</div>\n')

        todo = [x for x in todo if x not in done]

    out.write('<div class="log">')

    for msg in state.info:
        out.write('<p>%s</p>' % cgi.escape(str(msg)))

    for msg in state.errors:
        out.write('<p>%s</p>' % cgi.escape(str(msg)))

    out.write('</div>\n')

    out.write('</div>\n')

def set_maps(m):
    global maps
    maps = m


def gen_html(timeline, boundaries, out, write_op = None):
    global maps

    if timeline and not timeline[0]:
        timeline.pop(0)

    boundaries = list(sorted(boundaries))

    out.write('<style>')

    out.write('''body {
font-size: 12px;
background-color: #EBEBEB;
font-family: "Lucida Console", Monaco, monospace;
height: 100%;
width: 100%;
}''')

    out.write('''p {
margin: 0.8em 0 0 0.1em;
}
''')

    out.write('''.block {
float: left;
padding: 0.5em 0;
margin: 0.1em;
text-align: center;
color: black;
}
''')

    out.write('''.normal {
-webkit-border-radius: 0.25em; 
-moz-border-radius: 0.25em; 
border-radius: 0.25em; 
border:black solid 0.25em;
}
''')

    out.write('''.empty + .empty {
border-left: 1px solid gray;
margin-left: -1px;
}
''')

    out.write('''.empty {
color: gray;
}
''')

    out.write('''.line {  
display: flex;               /* establish flex container */
align-items: center; 
}
''')

    out.write('''.line:after {
  content:"";
  display:table;
  clear:both;
}
''')

    out.write('''.state {
margin: 0.5em; padding: 0;
background-color: white;
border-radius: 0.3em;
padding: 0.5em;
}''')

    out.write('''.log {
}''')

    out.write('''.error {
color: white;
background-color: #8b1820;
}''')

    out.write('''.error .empty {
color: white;
}''')

    out.write('''.timeline {
min-height: 100%%;
margin-bottom: -20%%;
width: %dem;
}
.infobox, .timeline:after {
  height: 20%%; 
}
.infobox {
  width: 103em;
}
.infochild {
overflow: hidden; 
position: relative;
float: left;
width: 50em;
height:100%%;
padding: 0.5em;
background: white;
border: black solid 0.25em;
}''' % ((len(boundaries) - 1) * (Printable.unit_width + 1.5)))

    out.write('</style>\n')

    out.write('<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>')
    out.write('''<script>
var scrollTimeout = null;
$(window).scroll(function(){
    if (scrollTimeout) clearTimeout(scrollTimeout);
    scrollTimeout = setTimeout(function(){
    $('.log').stop();
    $('.log').animate({
        'margin-left': $(this).scrollLeft()
    }, 100);
    }, 200);
});
</script>
''')

    writeJQuery(timeline, out)

    out.write('<body>\n')

    out.write('<div class="timeline">\n')

    for i,state in enumerate(timeline):
        print_state(out, boundaries, state)

    out.write('''<div class="infobox">
<div class="infochild" style="float: left;;">
<div style="float: left; width: 20em; height: 100%;;">
<strong>User addr: </strong>
<span id="uaddr"></span>
<br/>
<strong>User size: </strong>
<span id="usize"></span>
<br/>
<strong>Prev in use: </strong>
<span id="prev_inuse"></span>
<br/>
<strong>Is mmapped: </strong>
<span id="is_mmapped"></span>
<br/>
<strong>Non main arena: </strong>
<span id="non_main_arena"></span>
</div>
<div style="float: left; width: 20em; height: 100%;;">
<strong>Real addr: </strong>
<span id="raddr"></span>
<br/>
<strong>Real size: </strong>
<span id="rsize"></span>
<br/>
<strong>Fd: </strong>
<span id="fd"></span>
<br/>
<strong>Bk: </strong>
<span id="bk"></span>
</div>
</div>

<div class="infochild">
<strong>Libc segments:</strong><br/>
''')

    for line in maps.split('\n'):
        out.write('<span>' + line + '</span><br/>\n')

    out.write('</div>\n')
    out.write('</div>\n')
    out.write('</div>\n')

    out.write('</body>\n')


def writeJQuery(timeline, out) :

	tmp = ''

	for block in timeline[-1] :
		if isinstance(block, Block) : 
			tmp += '''$('#block%d').data('block', %s);
$('#block%d').click(handlerBlock);
''' % (block.id, block.to_json(), block.id)
		else :
			tmp += '''$('#empty%d').data('empty', %s);
$('#empty%d').click(handlerEmpty);
''' % (block.id, block.to_json(), block.id)
	
	string = '''<script>
function handlerBlock() {
	var block = $(this).data('block');
	var uaddr = block.uaddr;
	var usize = block.usize;
	var raddr = block.raddr;
	var rsize = block.rsize;
	$('#uaddr').html('0x' + uaddr.toString(16));
	$('#usize').html('0x' + usize.toString(16));
	$('#raddr').html('0x' + raddr.toString(16));
	$('#rsize').html('0x' + rsize.toString(16));
	$('#prev_inuse').html(block.prev_inuse);
	$('#is_mmapped').html(block.is_mmapped);
	$('#non_main_arena').html(block.non_main_arena);
	$('#fd').html('');
	$('#bk').html('');
}

function handlerEmpty() {
	var block = $(this).data('empty');
	var raddr = block.raddr;
	var rsize = block.rsize;
	var fd = block.fd;
	var bk = block.bk;
	$('#raddr').html('0x' + raddr.toString(16));
	$('#rsize').html('0x' + rsize.toString(16));
	$('#fd').html('0x' + fd.toString(16));
	$('#bk').html('0x' + bk.toString(16));
	$('#prev_inuse').html(block.prev_inuse);
	$('#is_mmapped').html(block.is_mmapped);
	$('#non_main_arena').html(block.non_main_arena);
	$('#uaddr').html('');
	$('#usize').html('');
}

$(document).ready(function(){
''' + tmp + '''
});
</script>
'''

	out.write(string)
