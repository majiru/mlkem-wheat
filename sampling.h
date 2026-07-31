void mlk_poly_cbd2(mlk_poly *r, const u8int buf[2 * MLKEM_N / 4]);
void mlk_poly_cbd3(mlk_poly *r, const u8int buf[3 * MLKEM_N / 4]);
void mlk_poly_rej_uniform(mlk_poly *entry, u8int seed[MLKEM_SYMBYTES + 2]);
