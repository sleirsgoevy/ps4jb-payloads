#pragma once

int register_fake_key(const char key_data[32]);
int unregister_fake_key(int key_id);
int get_fake_key(int key_id, char key_data[32]);
