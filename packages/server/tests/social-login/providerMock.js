import axios from 'axios';

export const providerMock = { respond: () => { throw new Error('Unexpected provider request'); } };
axios.defaults.adapter = async (config) => ({
  data: await providerMock.respond(config), status: 200, statusText: 'OK', headers: {}, config,
});
