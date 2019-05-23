import request from 'request';
import express, { Request, Response } from 'express';
import bodyParser from 'body-parser';
import compression from 'compression';
import crypto from 'crypto';

import { Logger, IPluginMiddleware, IBasicAuth, IStorageManager, PluginOptions } from '@verdaccio/types';
import { ConfigAudit } from './types';

const getSHA1 = (input) => {
    return crypto.createHash('sha1').update(JSON.stringify(input)).digest('hex');
};

export default class ProxyAudit implements IPluginMiddleware<ConfigAudit> {
  enabled: boolean;
  logger: Logger;
  cache: {[hash: string]: string} = {};

  constructor(config: ConfigAudit, options: PluginOptions<ConfigAudit>) {
    this.enabled = config.enabled || false;
    this.logger = options.logger;
  }

  register_middlewares(app: any, auth: IBasicAuth<ConfigAudit>, storage: IStorageManager<ConfigAudit>) {
    const fetchAudit = (req: Request, res: Response & { report_error?: Function }) => {
      const headers = req.headers;
      headers.host = 'https://registry.npmjs.org/';

      const requestCallback = (err, _res, body) => {
        if (_res.statusCode >= 500) {
          this.logger.warn('Request to registry failed ' + _res.statusCode);
          const cached = this.cache[getSHA1(req.body)];
          if (cached) {
            this.logger.info('Fetching from cache');
            delete this.cache[getSHA1(req.body)];
            return res.send(cached);
          }
          this.logger.warn('Retrying request to registry');
          return fetchAudit(req, res);
        }
        if (err) {
          if (typeof res.report_error === 'function') {
            return res.report_error(err);
          }
          this.logger.error(err);
          return res.status(500).end();
        }
        this.cache[getSHA1(req.body)] = body;
        
        res.send(body);
      };

      return request(
        {
          url: 'https://registry.npmjs.org/-/npm/v1/security/audits',
          method: 'POST',
          proxy: auth.config.https_proxy,
          body: JSON.stringify(req.body),
          gzip: true,
          strictSSL: true
        },
        requestCallback
      );
    };

    const handleAudit = (req: Request, res: Response) => {
      if (this.enabled) {
        fetchAudit(req, res);
      } else {
        res.status(500).end();
      }
    };

    /* eslint new-cap:off */
    const router = express.Router();
    /* eslint new-cap:off */
    router.use(compression());
    router.use(bodyParser.json({limit: '50mb'}));
    router.post('/audits', handleAudit);

    router.post('/audits/quick', handleAudit);

    app.use('/-/npm/v1/security', router);
  }
}
