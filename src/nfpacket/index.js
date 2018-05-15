const actions = require('./actions');
const encoding = require('./encoding');
const enums = require('./enums.js');

const setDirection = (state) => (direction) => {
  if (direction === 'incoming' || direction === 'outgoing') {
    state.direction = direction;
  } else {
    state.direction = undefined;
  }
}

const getDirection = (state) => () => {
  return state.direction;
}

const setInterface = (state) => (interface) => {
  state.interface = interface;
}

const getInterface = (state) => () => {
  return state.interface;
}

module.exports = (dependencies) => (nfpacket) => {
  let state = {
    nfpacket: nfpacket,
    enums: enums,
    direction: undefined,
    interface: undefined
  }
  if (Object.keys(dependencies).includes('nfq') && Object.keys(dependencies).includes('pcapIPv4')) {
    return Object.assign(
      {},
      {
        actions: actions(dependencies)(state),
        encoding: encoding(dependencies.pcapIPv4)(state),
        getDirection: getDirection(state),
        getInterface: getInterface(state),
        setDirection: setDirection(state),
        setInterface: setInterface(state),
        state
      }
    );
  }

  return false;
}
