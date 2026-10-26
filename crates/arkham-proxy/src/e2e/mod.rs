//! End-to-end proxy tests: real clients through the MITM against real
//! stub servers, per protocol and per transport.

mod amqp;
mod fixture;
mod http;
mod https;
mod ldap;
mod nats;
mod plugin;
mod postgres;
mod redis;
mod smtp;
mod tcp;
