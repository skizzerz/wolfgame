import rethinkdb as r
import fileinput
import re
import sys
import json
from datetime import datetime, timedelta

def main():
	conn = r.connect()
	conn.use('wolfgame')
	# init empty gamestate
	state = GameState(conn)
	inserted = 0
	for line in fileinput.input():
		state.add_line(line)
		if state.game_finished():
			doc = state.get_state()
			replace = state.replace
			state.reset()
			lines = { 'id': doc['id'], 'lines': doc['lines'] }
			del doc['lines']
			ins = r.table('games').insert(doc, upsert=True).run(conn)
			ins2 = r.table('lines').insert(lines, upsert=True).run(conn)

			if 'errors' in ins and ins['errors'] > 0:
				print (ins['first_error'])
				exit(1)
			elif 'errors' in ins2 and ins2['errors'] > 0:
				print (ins2['first_error'])
				exit(1)
			else:
				inserted += 1

	if state.game_running():
		print ("There is still a game running but we reached the end of input")
	
	print ("Inserted %d document(s), skipped %d document(s)" % (inserted, state.get_skipped()))
	exit(0)

class GameState:
	def __init__(self, db, botnicks = ["pywolf", "lycanthrope", "seerwolf", "lykos", "lykosmas", "lykos2014"], ownnicks = ["woffle", "moonmoon", "Skizzerz", "forest_fire", "wolfe"]):
		self.db = db
		self.botnicks = botnicks
		self.ownnicks = ownnicks
		self.othernicks = []
		self.skipped = 0
		# mapping of role name to key in roles (accounts for plural)
		self.rolemap = {
					'wolf': 'wolf',
					'wolves': 'wolf',
					'seer': 'seer',
					'seers': 'seer',
					'village drunk': 'drunk',
					'village drunks': 'drunk',
					'cursed villager': 'cursed',
					'cursed villagers': 'cursed',
					'harlot': 'harlot',
					'harlots': 'harlot',
					'gunner': 'gunner',
					'gunners': 'gunner',
					'traitor': 'traitor',
					'traitors': 'traitor',
					'werecrow': 'werecrow',
					'werecrows': 'werecrow',
					'detective': 'detective',
					'detectives': 'detective',
					'guardian angel': 'angel',
					'guardian angels': 'angel'
				}
		# which messages are associated with a lynch
		self.lynchmessages = [
					"The villagers, after much debate, finally decide on lynching (.*?), who turned out to be\.\.\. a .*?\.",
					"Under a lot of noise, the pitchfork-bearing villagers lynch (.*?), who turned out to be\.\.\. a .*?\.",
					"The mob drags a protesting (.*?) to the hanging tree",
					"Despite protests, the mob drags their victim to the hanging tree\. (.*?) succumbs to the will of the horde",
					"Resigned to (?:his/her fate|the inevitable), (.*?) is led to the gallows",
					"(?:As s/he is about to be lynched|Before the rope is pulled), (.*?), the .*?, throws a grenade at the mob",
					"As the real wolves run away from the murderous mob, (.*?) trips and falls",
					"As the sun sets, the villagers agree to retire to their beds and wait for morning", # no lynch
				]
		# which messages are associated with a kill
		self.killmessages = [
					".*? was attacked by the wolves last night",  # ga guarded, so kill is None
					"The wolves' selected victim was a harlot",   # harlot attacked, so kill is None
					"The dead body of (.*?), a .*?, is found",    # wolf kill
					"The body of a young penguin pet is found",   # wolves idle, so kill is None
					"A pool of blood and wolf paw prints are found" # ditto
					"Traces of wolf fur are found",               # ditto
					"(.*?), a .*?, made the unfortunate mistake", # harlot visited wolf or victim or ga guarded wolf
					"Fortunately, the victim, .*?, had bullets, and (.*?), a .*? was shot dead", # gunner killed wolf
				]
		# which messages are associated with a quit
		self.quitmessages = [
					".*? is forcing (.*?) to leave",                    # !fquit
					"(.*?) died of an unknown disease",                 # !quit
					"(.*?), a .*?, has died of an unknown disease",
					"(.*?) died due to falling off a cliff",            # /kick
					"(.*?) died due to a fatal attack by wild animals", # /quit
					"(.*?) was mauled by wild animals",
					"(.*?) died due to eating poisonous berries",       # /part
					"(.*?), a .*?, ate some poisonous berries"
				]
		# which messages are associated with an idle
		self.idlemessages = [
					"(.*?) didn't get out of bed for a very long time"  # idle
				]
		# which messages are associated with gunner shooting, indicate shot type as well
		# "shoot" is a special key to indicate that target should be applied as the gunner for the next gun message
		# (for miss/explode where the target isn't said in the message)
		self.shotmessages = [
					[".*? shoots (.*?) with a silver bullet", "shoot"],
					["(.*?) is a .*?, and is dying from the silver bullet", "kill"],
					["(.*?) is not a wolf but was accidentally fatally injured", "headshot"],
					["(.*?) is a villager and is injured", "hit"],
					[".*? is a lousy shooter", "miss"],
					[".*? should clean his/her weapons more often", "explode"],
					[".*?'s gun was poorly maintained and has exploded", "explode"]
				]
		# which roles are counted as wolfteam
		self.wolfroles = ['wolf', 'traitor', 'werecrow']
		self.reset()

	def reset(self):
		self.game = False
		self.finished = False
		self.nickmap = {}
		self.players = []
		self.roles = {}
		self.lines = []
		self.ruleset = {}
		self.killed = {}
		self.lynched = {}
		self.quit = []
		self.idled = []
		self.shot = {}
		self.nights = []
		self.days = []
		self.daytime = 0
		self.nighttime = 0
		self.gamesize = 0
		self.winner = "Unknown"
		self.id = 0 # id is the game start timestamp
		self.schema = 5
		self.replace = False
		self.curday = 0
		self.curnight = 0
		self.startfile = ""
		self.startline = 0
		self.options = {'wolfgunner': False, 'hiddentraitor': False, 'nightgunner': False}
		self.prevtarget = None

	def add_line(self, line):
		# Parse out timestamp, nick, and message
		line = line.strip()
		# strip formatting codes
		line = re.sub("\x1f|\x02|\x12|\x0f|\x16|\x03(?:\d{1,2}(?:,\d{1,2})?)?", '', line)
		m = re.match('\[([0-9:]+)\] (\*\*\*|\* [^ ]+|<.+?>) (.*)', line)
		if m == None:
			# blank line perhaps
			m = re.match('\[([0-9:]+)\] (\*\*\*|\* [^ ]+|<.+?>)', line)
			if m == None:
				print ("Unrecognized line " + line)
				return

		time = m.group(1)
		if m.group(2) == "***":
			nick = "**Server**"
			action = False
		else:
			if m.group(2)[0] == "*":
				nick = m.group(2)[2:]
				action = True
			else:
				nick = m.group(2)[1:-1]
				action = False

		if len(m.groups()) == 3:
			message = m.group(3)
		else:
			message = ''

		# Figure out full timestamp from the time + filename
		fname = fileinput.filename()
		m = re.search('([0-9]{4})/?([0-9]{2})/?([0-9]{2})', fname)
		if m == None:
			print ("Could not find timestamp for file " + fname)
			print ("Skipping file...")
			fileinput.nextfile()
			return
		timestamp = "%s%s%s%s%s%s" % (m.group(1), m.group(2), m.group(3), time[0:2], time[3:5], time[6:8])

		# If we or the bot joins/quits, wipe whatever current game is in progress as we lost it
		if nick == "**Server**":
			m = re.match('(?:Joins|Quits|Parts): (.*?) \((.*?)\)', message)
			if m != None:
				if m.group(1) in self.ownnicks or m.group(1) in self.botnicks:
					self.reset()
					return

		# Do we need to start a new game?
		m = re.match('(.*): Welcome to Werewolf, the popular detective/social party game \(a theme of Mafia\)\.', message)
		if m != None:
			if nick in self.botnicks:
				# if we are currently running a game, this is a bug
				if self.game:
					print ("!!! BUG !!! Starting a new game when a game is already running! File: %s Line: %s (started in %s at line %s)" % (fileinput.filename(), fileinput.filelineno(), self.startfile, self.startline))
					exit(1)
				# started a new game, first group is the nicks of who are playing
				self.game = True
				self.id = timestamp
				self.players = m.group(1).split(', ')
				self.gamesize = len(self.players)
				self.startfile = fileinput.filename()
				self.startline = fileinput.filelineno()
				# now set game options (wolfgunner, nightgunner, hiddentraitor)
				# wolfgunner and nightgunner are on if the game took place on or after 9/6/2013
				# hiddentraitor is on if the game took place on or after 2/10/2014
				if int(timestamp) > 20130906000000:
					self.options['wolfgunner'] = True
					self.options['nightgunner'] = True
				if int(timestamp) > 20140210000000:
					self.options['hiddentraitor'] = True
				# check if id already exists in the database, if so we can just skip over this game (saves a lot of processing/regexes)
				# only do this if we aren't updating the schema
				doc = r.table('games').get(self.id).run(self.db)
				if doc and doc['schema'] == self.schema:
					self.skipped += 1
					self.reset()
					return
				elif doc:
					self.replace = True
			elif nick not in self.othernicks:
				self.othernicks.append(nick)
				print ("Possible missed bot nick: %s" % nick)
		
		# If we have a game running, record the line
		if self.game:
			# determine realnick from nickmap
			realnick = self.nickmap.get(nick, nick)
			
			# determine if we need to add something to nickmap
			if nick == "**Server**":
				m = re.match('(.*?) is now known as (.*)', message)
				if m != None:
					oldnick = m.group(1)
					newnick = m.group(2)
					self.nickmap[newnick] = self.nickmap.get(oldnick, oldnick)
					if oldnick in self.botnicks:
						# if it is any of these people, the bot never actually changed
						never = ['Iciloo', 'sid|1']
						if newnick not in never:
							# HALP, THE BOT CHANGED NICKS
							print ("Bot changed nicks from %s to %s" % (oldnick, newnick))
							self.botnicks.append(newnick)
			
			# record the line
			try:
				self.lines.append({'timestamp': timestamp, 'nick': nick, 'realnick': realnick, 'message': unicode(message, 'utf-8'), 'action': action})
			except UnicodeDecodeError:
				# ignore the line
				return

			# If bot said something, figure out the action
			if nick in self.botnicks:
				# record lynches/kills/quits (!quit/kick)/idles (incl part and /quit)/shot
				# on lynch, increment days counter. on kill, increment nights counter
				# on shoot, record current day, who was shot, and shot outcome
				m = re.match('(Day|Night) lasted ([0-9]{2}):([0-9]{2})', message)
				if m != None:
					# increment days or nights (current day is self.days + 1)
					if m.group(1) == 'Day':
						self.days.append(int(m.group(2)) * 60 + int(m.group(3)))
						self.curday += 1
					elif m.group(1) == 'Night':
						self.nights.append(int(m.group(2)) * 60 + int(m.group(3)))
						self.curnight += 1
					return
				
				curday = str(self.curday + 1)
				curnight = str(self.curnight)

				for msg in self.lynchmessages:
					m = re.match(msg, message)
					if m != None:
						if curday not in self.lynched:
							self.lynched[curday] = []
						if len(m.groups()) == 1:
							# have a victim
							self.lynched[curday].append(m.group(1))
						return
				
				for msg in self.killmessages:
					m = re.match(msg, message)
					if m != None:
						if curnight not in self.killed:
							self.killed[curnight] = []
						if len(m.groups()) == 1:
							self.killed[curnight].append(m.group(1))
						return

				for msg in self.shotmessages:
					m = re.match(msg[0], message)
					if m != None:
						if curday not in self.shot:
							self.shot[curday] = []
						if msg[1] == "shoot":
							self.prevtarget = m.group(1)
							return
						elif msg[1] == "explode" or msg[1] == "miss":
							target = self.prevtarget
						else:
							target = m.group(1)
						self.shot[curday].append({'target': target, 'outcome': msg[1]})
						return

				for msg in self.quitmessages:
					m = re.match(msg, message)
					if m != None:
						self.quit.append(m.group(1))
						return

				for msg in self.idlemessages:
					m = re.match(msg, message)
					if m != None:
						self.idled.append(m.group(1))
						return

				# is game over?
				if not self.finished:
					# figure out who won
					m = re.match('(.*) has forced the game to stop', message)
					if m != None:
						# game was !fstopped, so wipe our slate
						self.reset()
						return
					m = re.match('Game over! (All the wolves are dead|There are).*', message)
					if m != None:
						self.finished = True
						if m.group(1) == 'All the wolves are dead':
							self.winner = "village"
						else:
							self.winner = "wolves"
						return
				else:
					# record time and role data and mark game as over
					# time is before role data, so don't mark over until we have both
					m = re.match('Game lasted ([0-9]+):([0-9]+)\. ([0-9]+):([0-9]+) was day\. ([0-9]+):([0-9]+) was night\.', message)
					if m != None:
						self.daytime = int(m.group(3)) * 60 + int(m.group(4))
						self.nighttime = int(m.group(5)) * 60 + int(m.group(6))
						return
					# if we get here, message is the listing of roles
					list = message.split('. ')
					for item in list:
						# remove any trailing periods
						item = item.rstrip('.')
						m = re.match('The (.*?) (were|was) (.*)', item)
						if m == None:
							print ("Failed to match regex to %s" % (message))
							continue
						# variable is a troll and faked some roles, so make sure we only record valid ones
						if m.group(1) not in self.rolemap:
							continue
						# determine the number of nicks in the 3rd group
						if m.group(2) == 'was':
							# one nick only, easy
							self.ruleset[self.rolemap[m.group(1)]] = 1
							self.roles[self.rolemap[m.group(1)]] = [m.group(3)]
						else:
							# multiple nicks, not so easy
							nicks = re.split(', (?:and )?| and ', m.group(3))
							self.ruleset[self.rolemap[m.group(1)]] = len(nicks)
							self.roles[self.rolemap[m.group(1)]] = nicks

					# finally mark the game as over
					self.game = False


	def get_state(self):
		# Be sure to increment schema if you change this
		state = {
					'id': self.id,
					'players': self.players,
					'roles': self.roles,
					'lines': self.lines,
					'ruleset': self.ruleset,
					'killed': self.killed,
					'lynched': self.lynched,
					'quit': self.quit,
					'idled': self.idled,
					'shot': self.shot,
					'nights': self.nights,
					'days': self.days,
					'nighttime': self.nighttime,
					'daytime': self.daytime,
					'gamesize': self.gamesize,
					'winner': self.winner,
					'schema': self.schema,
					'options': self.options
				}
		return state

	def game_running(self):
		return self.game

	def get_skipped(self):
		return self.skipped

	def game_finished(self):
		return self.finished and not self.game
	

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print ("Usage: python " + sys.argv[0] + " <logfile ...>")
		exit(0)
	main()
