const assert = require('assert');
const Draw = require('../public/sorteo-algo.js');

function namesFromSlots(slots) {
  return slots.map(slot => slot.code + ':' + slot.kind).join('|');
}

function positionByName(slots, name) {
  return slots.findIndex(function(slot) {
    return slot.kind === 'player' && slot.name === name;
  });
}

(function testDeterminism() {
  const players = [
    { pseudonimo: 'Alpha', division: 'Ciudad' },
    { pseudonimo: 'Bravo', division: 'Ciudad' },
    { pseudonimo: 'Charlie', division: 'Ciudad' },
    { pseudonimo: 'Delta', division: 'Ciudad' }
  ];
  const seedKey = Draw.makeDrawSeed({ randomness: 'abc123', fallback: false }, 'ciudad|16|Alpha,Bravo,Charlie,Delta');
  const first = Draw.buildSeededSlots(players, 'ciudad', 4, seedKey);
  const second = Draw.buildSeededSlots(players, 'ciudad', 4, seedKey);
  assert.strictEqual(namesFromSlots(first), namesFromSlots(second), 'Seeded shuffle must be deterministic');
})();

(function testSeedVariation() {
  const players = [
    { pseudonimo: 'Alpha', division: 'Ciudad' },
    { pseudonimo: 'Bravo', division: 'Ciudad' },
    { pseudonimo: 'Charlie', division: 'Ciudad' },
    { pseudonimo: 'Delta', division: 'Ciudad' }
  ];
  const seedA = Draw.makeDrawSeed({ randomness: 'aaa', fallback: false }, 'ciudad|16|Alpha,Bravo,Charlie,Delta');
  const seedB = Draw.makeDrawSeed({ randomness: 'bbb', fallback: false }, 'ciudad|16|Alpha,Bravo,Charlie,Delta');
  const first = Draw.buildSeededSlots(players, 'ciudad', 4, seedA);
  const second = Draw.buildSeededSlots(players, 'ciudad', 4, seedB);
  assert.notStrictEqual(namesFromSlots(first), namesFromSlots(second), 'Different seeds should change order');
})();

(function testOpenSlots() {
  const players = [{ pseudonimo: 'Alpha', division: 'Universal' }];
  const seedKey = Draw.makeDrawSeed({ randomness: 'abc123', fallback: false }, 'universal|16|Alpha');
  const slots = Draw.buildSeededSlots(players, 'universal', 4, seedKey);
  assert.strictEqual(slots.length, 4, 'Bracket size should be respected');
  const openCount = slots.filter(slot => slot.kind === 'open').length;
  assert.strictEqual(openCount, 3, 'Open slots should fill remaining positions');
})();

(function testFallbackSeed() {
  const seedKey = Draw.makeDrawSeed({ fallback: true }, 'ciudad|16|Alpha');
  assert.ok(seedKey.startsWith('bellator-fallback|'), 'Fallback seed should be deterministic');
})();

(function testProgressiveSlotsStayFixed() {
  const seedKey = 'bellator-fixed-slots|ciudad|16';
  const first = Draw.buildProgressiveSlots([
    { pseudonimo: 'Abyssilum', division: 'Ciudad', timestamp: '2026-05-10T10:00:00Z' },
    { pseudonimo: 'Ryu', division: 'Ciudad', timestamp: '2026-05-10T10:15:00Z' }
  ], 'ciudad', 8, seedKey);
  const expanded = Draw.buildProgressiveSlots([
    { pseudonimo: 'Abyssilum', division: 'Ciudad', timestamp: '2026-05-10T10:00:00Z' },
    { pseudonimo: 'Ryu', division: 'Ciudad', timestamp: '2026-05-10T10:15:00Z' },
    { pseudonimo: 'Khan', division: 'Ciudad', timestamp: '2026-05-10T10:30:00Z' },
    { pseudonimo: 'Selene', division: 'Ciudad', timestamp: '2026-05-10T10:45:00Z' }
  ], 'ciudad', 8, seedKey);

  assert.strictEqual(
    positionByName(expanded, 'Abyssilum'),
    positionByName(first, 'Abyssilum'),
    'Existing approved players must keep the same slot'
  );
  assert.strictEqual(
    positionByName(expanded, 'Ryu'),
    positionByName(first, 'Ryu'),
    'Existing pairings must not move when new players arrive'
  );
})();

(function testProgressiveSlotsAreNotSequential() {
  const seedKey = 'bellator-fixed-slots|ciudad|16';
  const slots = Draw.buildProgressiveSlots([
    { pseudonimo: 'Abyssilum', division: 'Ciudad', timestamp: '2026-05-10T10:00:00Z' },
    { pseudonimo: 'Ryu', division: 'Ciudad', timestamp: '2026-05-10T10:15:00Z' },
    { pseudonimo: 'Khan', division: 'Ciudad', timestamp: '2026-05-10T10:30:00Z' }
  ], 'ciudad', 8, seedKey);

  assert.notStrictEqual(
    positionByName(slots, 'Khan'),
    2,
    'A newcomer should not always land in the next sequential slot'
  );
})();

(function testProgressiveSlotsIgnoreRenameWhenTimestampIsStable() {
  const seedKey = 'bellator-fixed-slots|ciudad|16';
  const before = Draw.buildProgressiveSlots([
    { pseudonimo: 'Abyssilum', division: 'Ciudad', timestamp: '2026-05-10T10:00:00Z' }
  ], 'ciudad', 8, seedKey);
  const after = Draw.buildProgressiveSlots([
    { pseudonimo: 'Abyss', division: 'Ciudad', timestamp: '2026-05-10T10:00:00Z' }
  ], 'ciudad', 8, seedKey);

  assert.strictEqual(
    positionByName(before, 'Abyssilum'),
    positionByName(after, 'Abyss'),
    'Changing profile text should not move a slot while approval timestamp is the same'
  );
})();

(function testUniversalTwelveSlotPairingsStaySequential() {
  const players = Array.from({ length: 12 }, function(_, index) {
    return {
      pseudonimo: 'Universal-' + String(index + 1).padStart(2, '0'),
      division: 'Universal'
    };
  });

  const matches = Draw.buildOrderedPairingMatches(players, 'universal', 12);

  assert.strictEqual(matches.length, 6, '12-slot Universal board should show 6 pre-set duels');
  assert.strictEqual(matches[0].teams[0].name, 'Universal-01', 'First duel should keep player 1');
  assert.strictEqual(matches[0].teams[1].name, 'Universal-02', 'First duel should keep player 2');
  assert.strictEqual(matches[5].teams[0].name, 'Universal-11', 'Last duel should keep player 11');
  assert.strictEqual(matches[5].teams[1].name, 'Universal-12', 'Last duel should keep player 12');
})();

console.log('sorteo-algo tests: OK');
